// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/redirectpolicy"
)

type Metrics struct {
	DPMode                        metric.Vec[metric.Gauge]
	DPIPAM                        metric.Vec[metric.Gauge]
	DPChaining                    metric.Vec[metric.Gauge]
	DPIP                          metric.Vec[metric.Gauge]
	DPIdentityAllocation          metric.Vec[metric.Gauge]
	DPCiliumEndpointSlicesEnabled metric.Gauge
	DPDeviceMode                  metric.Vec[metric.Gauge]

	NPHostFirewallEnabled        metric.Gauge
	NPLocalRedirectPolicyEnabled metric.Gauge
	NPMutualAuthEnabled          metric.Gauge

	NPL3L4Ingested              metric.Gauge
	NPL3L4Present               metric.Gauge
	NPCCNPIngested              metric.Gauge
	NPCCNPPresent               metric.Gauge
	NPHostNPIngested            metric.Gauge
	NPHostNPPresent             metric.Gauge
	NPDNSIngested               metric.Gauge
	NPDNSPresent                metric.Gauge
	NPHTTPIngested              metric.Gauge
	NPHTTPPresent               metric.Gauge
	NPOtherL7Ingested           metric.Gauge
	NPOtherL7Present            metric.Gauge
	NPLRPIngested               metric.Gauge
	NPLRPPresent                metric.Gauge
	NPDenyPoliciesIngested      metric.Gauge
	NPDenyPoliciesPresent       metric.Gauge
	NPIngressCIDRGroupIngested  metric.Gauge
	NPIngressCIDRGroupPresent   metric.Gauge
	NPMutualAuthIngested        metric.Gauge
	NPMutualAuthPresent         metric.Gauge
	NPTLSInspectionIngested     metric.Gauge
	NPTLSInspectionPresent      metric.Gauge
	NPSNIAllowListIngested      metric.Gauge
	NPSNIAllowListPresent       metric.Gauge
	NPHTTPHeaderMatchesIngested metric.Gauge
	NPHTTPHeaderMatchesPresent  metric.Gauge
	NPNonDefaultDenyIngested    metric.Gauge
	NPNonDefaultDenyPresent     metric.Gauge

	NPCIDRPoliciesToNodes     metric.Vec[metric.Gauge]
	ACLBTransparentEncryption metric.Vec[metric.Gauge]
}

const (
	subsystemDP   = "_feature_datapath"
	subsystemNP   = "_feature_network_policies"
	subsystemACLB = "_feature_adv_connect_and_lb"
)

func newMetrics() Metrics {
	return Metrics{
		DPMode: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "Network mode enabled on the agent",
			Name:      "network",
		}, metric.Labels{
			{Name: "mode", Values: metric.NewValues("overlay-vxlan", "overlay-geneve", "direct-routing")},
		}),

		DPIPAM: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "IPAM mode enabled on the agent",
			Name:      "ipam",
		}, metric.Labels{
			{Name: "mode", Values: metric.NewValues(
				ipamOption.IPAMKubernetes,
				ipamOption.IPAMCRD,
				ipamOption.IPAMENI,
				ipamOption.IPAMAzure,
				ipamOption.IPAMClusterPool,
				ipamOption.IPAMMultiPool,
				ipamOption.IPAMAlibabaCloud,
				ipamOption.IPAMDelegatedPlugin,
			)},
		}),

		DPChaining: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "Chaining mode enabled on the agent",
			Name:      "chaining",
		}, metric.Labels{
			{Name: "mode", Values: metric.NewValues("aws-vpc-cni", "flannel", "calico")},
		}),

		DPIP: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "IP mode enabled on the agent",
			Name:      "internet_protocol",
		}, metric.Labels{
			{Name: "protocol", Values: metric.NewValues("ipv4-only", "ipv6-only", "ipv4-ipv6-dual-stack")},
		}),

		DPIdentityAllocation: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "Identity Allocation mode enabled on the agent",
			Name:      "identity_allocation",
		}, metric.Labels{
			{Name: "mode", Values: metric.NewValues(
				option.IdentityAllocationModeKVstore,
				option.IdentityAllocationModeCRD,
				option.IdentityAllocationModeDoubleWriteReadKVstore,
				option.IdentityAllocationModeDoubleWriteReadKVstore,
			)},
		}),

		DPCiliumEndpointSlicesEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "Cilium Endpoint Slices enabled on the agent",
			Name:      "cilium_endpoint_slices_enabled",
		}),

		DPDeviceMode: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "Device Mode enabled on the agent",
			Name:      "device",
		}, metric.Labels{
			{Name: "mode", Values: metric.NewValues(
				datapathOption.DatapathModeVeth,
				datapathOption.DatapathModeNetkit,
				datapathOption.DatapathModeNetkitL2,
				datapathOption.DatapathModeLBOnly,
			)},
		}),

		NPHostFirewallEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Host firewall enabled on the agent",
			Name:      "host_firewall_enabled",
		}),

		NPLocalRedirectPolicyEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Local Redirect Policy enabled on the agent",
			Name:      "local_redirect_policy_enabled",
		}),

		NPMutualAuthEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Mutual Auth enabled on the agent",
			Name:      "mutual_auth_enabled",
		}),

		NPL3L4Ingested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Layer 3 and Layer 4 policies have been ingested since the agent started",
			Name:      "l3_l4_policies_ingested",
		}),

		NPL3L4Present: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Number of Layer 3 and Layer 4 policies are currently present in the agent",
			Name:      "l3_l4_policies_present",
		}),

		NPCCNPIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Cilium Clusterwide Network Policies have been ingested since the agent started",
			Name:      "cilium_clusterwide_network_policies_ingested",
		}),

		NPCCNPPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Cilium Clusterwide Network Policies are currently present in the agent",
			Name:      "cilium_clusterwide_network_policies_present",
		}),

		NPHostNPIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Host Network Policies have been ingested since the agent started",
			Name:      "host_network_policies_ingested",
		}),

		NPHostNPPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Host Network Policies are currently present in the agent",
			Name:      "host_network_policies_present",
		}),

		NPDNSIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "DNS Policies have been ingested since the agent started",
			Name:      "dns_policies_ingested",
		}),

		NPDNSPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "DNS Policies are currently present in the agent",
			Name:      "dns_policies_present",
		}),

		NPHTTPIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "HTTP/GRPC Policies have been ingested since the agent started",
			Name:      "http_policies_ingested",
		}),

		NPHTTPPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "HTTP/GRPC Policies are currently present in the agent",
			Name:      "http_policies_present",
		}),

		NPOtherL7Ingested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Other L7 Policies have been ingested since the agent started",
			Name:      "other_l7_policies_ingested",
		}),

		NPOtherL7Present: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Other L7 Policies are currently present in the agent",
			Name:      "other_l7_policies_present",
		}),

		NPLRPIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Local Redirect Policies have been ingested since the agent started",
			Name:      "local_redirect_policies_ingested",
		}),

		NPLRPPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Local Redirect Policies are currently present in the agent",
			Name:      "local_redirect_policies_present",
		}),

		NPDenyPoliciesIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Deny Policies have been ingested since the agent started",
			Name:      "deny_policies_ingested",
		}),

		NPDenyPoliciesPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Deny Policies are currently present in the agent",
			Name:      "deny_policies_present",
		}),

		NPIngressCIDRGroupIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Ingress CIDR Group Policies have been ingested since the agent started",
			Name:      "ingress_cidr_group_policies_ingested",
		}),

		NPIngressCIDRGroupPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Ingress CIDR Group Policies are currently present in the agent",
			Name:      "ingress_cidr_group_policies_present",
		}),

		NPMutualAuthIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Mutual Auth Policies have been ingested since the agent started",
			Name:      "mutual_auth_policies_ingested",
		}),

		NPMutualAuthPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Mutual Auth Policies are currently present in the agent",
			Name:      "mutual_auth_policies_present",
		}),

		NPTLSInspectionIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "TLS Inspection Policies have been ingested since the agent started",
			Name:      "tls_inspection_policies_ingested",
		}),

		NPTLSInspectionPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "TLS Inspection Policies are currently present in the agent",
			Name:      "tls_inspection_policies_present",
		}),

		NPSNIAllowListIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "SNI Allow List Policies have been ingested since the agent started",
			Name:      "sni_allow_list_policies_ingested",
		}),

		NPSNIAllowListPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "SNI Allow List Policies are currently present in the agent",
			Name:      "sni_allow_list_policies_present",
		}),

		NPHTTPHeaderMatchesIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "HTTP HeaderMatches Policies have been ingested since the agent started",
			Name:      "http_header_matches_policies_ingested",
		}),

		NPHTTPHeaderMatchesPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "HTTP HeaderMatches Policies are currently present in the agent",
			Name:      "http_header_matches_policies_present",
		}),

		NPNonDefaultDenyIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Non DefaultDeny Policies have been ingested since the agent started",
			Name:      "non_defaultdeny_policies_ingested",
		}),

		NPNonDefaultDenyPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Non DefaultDeny Policies are currently present in the agent",
			Name:      "non_defaultdeny_policies_present",
		}),

		NPCIDRPoliciesToNodes: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Mode to apply CIDR Policies",
			Name:      "cidr_policies",
		}, metric.Labels{
			{Name: "mode", Values: metric.NewValues(
				"world",
				"remote-node",
			)},
		}),

		ACLBTransparentEncryption: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "Encryption mode enabled on the agent",
			Name:      "transparent_encryption",
		}, metric.Labels{
			{Name: "mode", Values: metric.NewValues(
				"ipsec",
				"wireguard",
			)},
			{Name: "node2node_enabled", Values: metric.NewValues(
				"true",
				"false",
			)},
		}),
	}
}

type featureMetrics interface {
	updateMetrics(params featuresParams, config *option.DaemonConfig)
}

type RuleFeatures struct {
	L3                bool
	Host              bool
	DNS               bool
	HTTP              bool
	OtherL7           bool
	Deny              bool
	IngressCIDRGroup  bool
	MutualAuth        bool
	TLSInspection     bool
	SNIAllowList      bool
	HTTPHeaderMatches bool
	NonDefaultDeny    bool
}

func (m Metrics) AddRule(r api.Rule) {
	rf := ruleType(r)

	if rf.L3 {
		m.NPL3L4Ingested.Set(1)
		m.NPL3L4Present.Inc()
	}
	if rf.Host {
		m.NPHostNPIngested.Set(1)
		m.NPHostNPPresent.Inc()
	}
	if rf.DNS {
		m.NPDNSIngested.Set(1)
		m.NPDNSPresent.Inc()
	}
	if rf.HTTP {
		m.NPHTTPIngested.Set(1)
		m.NPHTTPPresent.Inc()
	}
	if rf.OtherL7 {
		m.NPOtherL7Ingested.Set(1)
		m.NPOtherL7Present.Inc()
	}
	if rf.Deny {
		m.NPDenyPoliciesIngested.Set(1)
		m.NPDenyPoliciesPresent.Inc()
	}
	if rf.IngressCIDRGroup {
		m.NPIngressCIDRGroupIngested.Set(1)
		m.NPIngressCIDRGroupPresent.Inc()
	}
	if rf.MutualAuth {
		m.NPMutualAuthIngested.Set(1)
		m.NPMutualAuthPresent.Inc()
	}
	if rf.TLSInspection {
		m.NPTLSInspectionIngested.Set(1)
		m.NPTLSInspectionPresent.Inc()
	}
	if rf.SNIAllowList {
		m.NPSNIAllowListIngested.Set(1)
		m.NPSNIAllowListPresent.Inc()
	}
	if rf.HTTPHeaderMatches {
		m.NPHTTPHeaderMatchesIngested.Set(1)
		m.NPHTTPHeaderMatchesPresent.Inc()
	}
	if rf.NonDefaultDeny {
		m.NPNonDefaultDenyIngested.Set(1)
		m.NPNonDefaultDenyPresent.Inc()
	}
}

func ruleType(r api.Rule) RuleFeatures {
	var rf RuleFeatures

	rf.NonDefaultDeny = r.EnableDefaultDeny.Ingress != nil || r.EnableDefaultDeny.Egress != nil

	for _, i := range r.Ingress {
		if len(i.IngressCommonRule.FromNodes) > 0 {
			rf.Host = true
			rf.L3 = true
		}
		if !rf.L3 && i.IngressCommonRule.IsL3() {
			rf.L3 = true
		}
		if i.Authentication != nil {
			rf.MutualAuth = true
		}
		if !rf.TLSInspection || !rf.SNIAllowList {
			for _, p := range i.ToPorts {
				if !rf.TLSInspection && (p.OriginatingTLS != nil || p.TerminatingTLS != nil) {
					rf.TLSInspection = true
				}
				if !rf.SNIAllowList && len(p.ServerNames) != 0 {
					rf.SNIAllowList = true
				}
				// We shouldn't accept such rules
				// if len(p.Rules.DNS) > 0 {
				// 	rf.DNS = true
				// }
				if len(p.Rules.HTTP) > 0 {
					rf.HTTP = true
					if !rf.HTTPHeaderMatches {
						for _, httpRule := range p.Rules.HTTP {
							if len(httpRule.HeaderMatches) > 0 {
								rf.HTTPHeaderMatches = true
							}
						}
					}
				}
				if len(p.Rules.L7) > 0 || len(p.Rules.Kafka) > 0 {
					rf.OtherL7 = true
				}
				if rf.DNS && rf.HTTP && rf.OtherL7 && rf.TLSInspection && rf.SNIAllowList && rf.HTTPHeaderMatches {
					break
				}
			}
		}
		if rf.L3 && rf.Host && rf.MutualAuth && rf.TLSInspection && rf.SNIAllowList {
			break
		}
	}

	if !rf.L3 || !rf.Host {
		for _, i := range r.IngressDeny {
			rf.Deny = true
			if len(i.IngressCommonRule.FromNodes) > 0 {
				rf.Host = true
				rf.L3 = true
			}
			for _, cidrRuleSet := range i.IngressCommonRule.FromCIDRSet {
				if cidrRuleSet.CIDRGroupRef != "" {
					rf.IngressCIDRGroup = true
					rf.L3 = true
				}
			}
			if !rf.L3 && i.IngressCommonRule.IsL3() {
				rf.L3 = true
			}
			if rf.L3 && rf.Host && rf.Deny {
				break
			}
		}
	}

	if !rf.L3 || !rf.Host {
		for _, e := range r.Egress {
			if len(e.EgressCommonRule.ToNodes) > 0 {
				rf.Host = true
				rf.L3 = true
			}

			if !rf.L3 && e.EgressCommonRule.IsL3() {
				rf.L3 = true
			}

			if !rf.DNS || !rf.HTTP || !rf.OtherL7 || !rf.TLSInspection || !rf.SNIAllowList || !rf.HTTPHeaderMatches {
				if len(e.ToFQDNs) > 0 {
					rf.DNS = true
				}
				for _, p := range e.ToPorts {
					if !rf.TLSInspection && (p.OriginatingTLS != nil || p.TerminatingTLS != nil) {
						rf.TLSInspection = true
					}
					if !rf.SNIAllowList && len(p.ServerNames) != 0 {
						rf.SNIAllowList = true
					}
					if len(p.Rules.DNS) > 0 {
						rf.DNS = true
					}
					if len(p.Rules.HTTP) > 0 {
						rf.HTTP = true
						if !rf.HTTPHeaderMatches {
							for _, httpRule := range p.Rules.HTTP {
								if len(httpRule.HeaderMatches) > 0 {
									rf.HTTPHeaderMatches = true
								}
							}
						}
					}
					if len(p.Rules.L7) > 0 || len(p.Rules.Kafka) > 0 {
						rf.OtherL7 = true
					}
					if rf.DNS && rf.HTTP && rf.OtherL7 && rf.TLSInspection && rf.SNIAllowList && rf.HTTPHeaderMatches {
						break
					}
				}
			}
			if e.Authentication != nil {
				rf.MutualAuth = true
			}

			if rf.L3 && rf.Host && rf.DNS && rf.HTTP && rf.OtherL7 && rf.MutualAuth && rf.TLSInspection && rf.SNIAllowList {
				break
			}
		}
	}

	if !rf.L3 || !rf.Host || !rf.Deny {
		for _, e := range r.EgressDeny {
			rf.Deny = true
			if len(e.EgressCommonRule.ToNodes) > 0 {
				rf.Host = true
				rf.L3 = true
			}

			if !rf.L3 && e.EgressCommonRule.IsL3() {
				rf.L3 = true
			}

			if rf.L3 && rf.Host && rf.Deny {
				break
			}
		}
	}
	return rf
}

func (m Metrics) DelRule(r api.Rule) {
	rf := ruleType(r)

	if rf.L3 {
		m.NPL3L4Present.Dec()
	}
	if rf.Host {
		m.NPHostNPPresent.Dec()
	}
	if rf.DNS {
		m.NPDNSPresent.Dec()
	}
	if rf.HTTP {
		m.NPHTTPPresent.Dec()
	}
	if rf.OtherL7 {
		m.NPOtherL7Present.Dec()
	}
	if rf.Deny {
		m.NPDenyPoliciesPresent.Dec()
	}
	if rf.IngressCIDRGroup {
		m.NPIngressCIDRGroupPresent.Dec()
	}
	if rf.MutualAuth {
		m.NPMutualAuthPresent.Dec()
	}
	if rf.TLSInspection {
		m.NPTLSInspectionPresent.Dec()
	}
	if rf.SNIAllowList {
		m.NPSNIAllowListPresent.Dec()
	}
	if rf.HTTPHeaderMatches {
		m.NPHTTPHeaderMatchesPresent.Dec()
	}
	if rf.NonDefaultDeny {
		m.NPNonDefaultDenyPresent.Dec()
	}
}

func (m Metrics) AddConfig(cfg *redirectpolicy.LRPConfig) {
	m.NPLRPIngested.Set(1)
	m.NPLRPPresent.Inc()
}

func (m Metrics) DelConfig(cfg *redirectpolicy.LRPConfig) {
	m.NPLRPPresent.Dec()
}

func (m Metrics) updateMetrics(params featuresParams, config *option.DaemonConfig) {
	networkMode := "direct-routing"
	if config.TunnelingEnabled() {
		switch params.TunnelConfig.Protocol() {
		case tunnel.VXLAN:
			networkMode = "overlay-vxlan"
		case tunnel.Geneve:
			networkMode = "overlay-geneve"
		}
	}

	ipamMode := config.IPAM

	chainingMode := params.CNIConfigManager.GetChainingMode()

	var ip string
	switch {
	case config.IsDualStack():
		ip = "ipv4-ipv6-dual-stack"
	case config.IPv4Enabled():
		ip = "ipv4-only"
	case config.IPv6Enabled():
		ip = "ipv6-only"
	}

	identityAllocationMode := config.IdentityAllocationMode

	deviceMode := config.DatapathMode

	m.DPMode.WithLabelValues(networkMode).Set(1)
	m.DPIPAM.WithLabelValues(ipamMode).Set(1)
	m.DPChaining.WithLabelValues(chainingMode).Set(1)
	m.DPIP.WithLabelValues(ip).Set(1)
	m.DPIdentityAllocation.WithLabelValues(identityAllocationMode).Set(1)
	m.DPDeviceMode.WithLabelValues(deviceMode).Set(1)

	if config.EnableCiliumEndpointSlice {
		m.DPCiliumEndpointSlicesEnabled.Set(1)
	}
	if config.EnableHostFirewall {
		m.NPHostFirewallEnabled.Set(1)
	}
	if config.EnableLocalRedirectPolicy {
		m.NPLocalRedirectPolicyEnabled.Set(1)
	}
	if params.MutualAuth.IsEnabled() {
		m.NPMutualAuthEnabled.Set(1)
	}
	for _, mode := range config.PolicyCIDRMatchMode {
		m.NPCIDRPoliciesToNodes.WithLabelValues(mode).Set(1)
	}
	if config.EnableIPSec {
		m.ACLBTransparentEncryption.WithLabelValues("ipsec", "false").Set(1)
	}
	if config.EnableWireguard {
		if config.EncryptNode {
			m.ACLBTransparentEncryption.WithLabelValues("wireguard", "true").Set(1)
		} else {
			m.ACLBTransparentEncryption.WithLabelValues("wireguard", "false").Set(1)
		}
	}
}
