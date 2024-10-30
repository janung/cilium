// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/redirectpolicy"
)

type Metrics struct {
	DPMode                        metric.Vec[metric.Counter]
	DPIPAM                        metric.Vec[metric.Counter]
	DPChaining                    metric.Vec[metric.Counter]
	DPIP                          metric.Vec[metric.Counter]
	DPIdentityAllocation          metric.Vec[metric.Counter]
	DPCiliumEndpointSlicesEnabled metric.Counter
	DPDeviceMode                  metric.Vec[metric.Counter]

	NPHostFirewallEnabled        metric.Counter
	NPLocalRedirectPolicyEnabled metric.Counter
	NPMutualAuthEnabled          metric.Counter

	NPL3L4Ingested              metric.Counter
	NPL3L4Present               metric.Gauge
	NPCCNPIngested              metric.Counter
	NPCCNPPresent               metric.Gauge
	NPHostNPIngested            metric.Counter
	NPHostNPPresent             metric.Gauge
	NPDNSIngested               metric.Counter
	NPDNSPresent                metric.Gauge
	NPHTTPIngested              metric.Counter
	NPHTTPPresent               metric.Gauge
	NPOtherL7Ingested           metric.Counter
	NPOtherL7Present            metric.Gauge
	NPLRPIngested               metric.Counter
	NPLRPPresent                metric.Gauge
	NPDenyPoliciesIngested      metric.Counter
	NPDenyPoliciesPresent       metric.Gauge
	NPIngressCIDRGroupIngested  metric.Counter
	NPIngressCIDRGroupPresent   metric.Gauge
	NPMutualAuthIngested        metric.Counter
	NPMutualAuthPresent         metric.Gauge
	NPTLSInspectionIngested     metric.Counter
	NPTLSInspectionPresent      metric.Gauge
	NPSNIAllowListIngested      metric.Counter
	NPSNIAllowListPresent       metric.Gauge
	NPHTTPHeaderMatchesIngested metric.Counter
	NPHTTPHeaderMatchesPresent  metric.Gauge
	NPNonDefaultDenyEnabled     metric.Counter
	NPNonDefaultDenyIngested    metric.Counter
	NPNonDefaultDenyPresent     metric.Gauge

	NPCIDRPoliciesToNodes                    metric.Vec[metric.Counter]
	ACLBTransparentEncryption                metric.Vec[metric.Counter]
	ACLBKubeProxyReplacementEnabled          metric.Counter
	ACLBStandaloneNSLB                       metric.Vec[metric.Counter]
	ACLBBGPAdvertisementEnabled              metric.Counter
	ACLBEgressGatewayEnabled                 metric.Counter
	ACLBBandwidthManagerEnabled              metric.Counter
	ACLBSRv6Enabled                          metric.Counter
	ACLBSCTPEnabled                          metric.Counter
	ACLBInternalTrafficPolicyEnabled         metric.Counter
	ACLBInternalTrafficPolicyIngested        metric.Counter
	ACLBInternalTrafficPolicyPresent         metric.Gauge
	ACLBCiliumEnvoyConfigEnabled             metric.Counter
	ACLBCiliumEnvoyConfigIngested            metric.Counter
	ACLBCiliumEnvoyConfigPresent             metric.Gauge
	ACLBCiliumClusterwideEnvoyConfigIngested metric.Counter
	ACLBCiliumClusterwideEnvoyConfigPresent  metric.Gauge
	ACLBVTEPEnabled                          metric.Counter
	ACLBBigTCPEnabled                        metric.Vec[metric.Counter]
	ACLBL2LBEnabled                          metric.Counter
	ACLBExternalEnvoyProxyEnabled            metric.Vec[metric.Counter]
	ACLBCiliumNodeConfigEnabled              metric.Counter
}

const (
	subsystemDP   = "_feature_datapath"
	subsystemNP   = "_feature_network_policies"
	subsystemACLB = "_feature_adv_connect_and_lb"
)

func newMetrics() Metrics {
	return Metrics{
		DPMode: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "Network mode enabled on the agent",
			Name:      "network",
		}, metric.Labels{
			{Name: "mode"},
		}),

		DPIPAM: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "IPAM mode enabled on the agent",
			Name:      "ipam",
		}, metric.Labels{
			{Name: "mode"},
		}),

		DPChaining: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "Chaining mode enabled on the agent",
			Name:      "chaining",
		}, metric.Labels{
			{Name: "mode"},
		}),

		DPIP: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "IP mode enabled on the agent",
			Name:      "internet_protocol",
		}, metric.Labels{
			{Name: "protocol"},
		}),

		DPIdentityAllocation: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "Identity Allocation mode enabled on the agent",
			Name:      "identity_allocation",
		}, metric.Labels{
			{Name: "mode"},
		}),

		DPCiliumEndpointSlicesEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "Cilium Endpoint Slices enabled on the agent",
			Name:      "cilium_endpoint_slices_enabled",
		}),

		DPDeviceMode: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "Device Mode enabled on the agent",
			Name:      "device",
		}, metric.Labels{
			{Name: "mode"},
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

		NPNonDefaultDenyEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Non DefaultDeny Policies is enabled in the agent",
			Name:      "non_defaultdeny_policies_enabled",
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

		NPCIDRPoliciesToNodes: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Mode to apply CIDR Policies",
			Name:      "cidr_policies",
		}, metric.Labels{
			{Name: "mode"},
		}),

		ACLBTransparentEncryption: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "Encryption mode enabled on the agent",
			Name:      "transparent_encryption",
		}, metric.Labels{
			{Name: "mode"},
			{Name: "node2node_enabled"},
		}),

		ACLBKubeProxyReplacementEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "KubeProxyReplacement enabled on the agent",
			Name:      "kube_proxy_replacement_enabled",
		}),

		ACLBStandaloneNSLB: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "Standalone North-South Load Balancer configuration enabled on the agent",
			Name:      "standalone_ns_lb",
		}, metric.Labels{
			{Name: "mode"},
			{Name: "algorithm"},
			{Name: "acceleration"},
		}),

		ACLBBGPAdvertisementEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "BGP Advertisement enabled on the agent",
			Name:      "bgp_advertisement_enabled",
		}),

		ACLBEgressGatewayEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "Egress Gateway enabled on the agent",
			Name:      "egress_gateway_enabled",
		}),

		ACLBBandwidthManagerEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "Bandwidth Manager enabled on the agent",
			Name:      "bandwidth_manager_enabled",
		}),

		ACLBSRv6Enabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "SRv6 enabled on the agent",
			Name:      "srv6_enabled",
		}),

		ACLBSCTPEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "SCTP enabled on the agent",
			Name:      "sctp_enabled",
		}),

		ACLBInternalTrafficPolicyEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "K8s Internal Traffic Policy enabled on the agent",
			Name:      "k8s_internal_traffic_policy_enabled",
		}),

		ACLBInternalTrafficPolicyIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "K8s Services with Internal Traffic Policy have been ingested since the agent started",
			Name:      "internal_traffic_policy_services_ingested",
		}),

		ACLBInternalTrafficPolicyPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "K8s Services with Internal Traffic Policy are currently present in the agent",
			Name:      "internal_traffic_policy_services_present",
		}),

		ACLBCiliumEnvoyConfigEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "Cilium Envoy Config enabled on the agent",
			Name:      "cilium_envoy_config_enabled",
		}),

		ACLBCiliumEnvoyConfigIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Cilium Envoy Config have been ingested since the agent started",
			Name:      "cilium_envoy_config_ingested",
		}),

		ACLBCiliumEnvoyConfigPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Cilium Envoy Config are currently present in the agent",
			Name:      "cilium_envoy_config_present",
		}),

		ACLBCiliumClusterwideEnvoyConfigIngested: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Cilium Clusterwide Envoy Config have been ingested since the agent started",
			Name:      "cilium_clusterwide_envoy_config_ingested",
		}),

		ACLBCiliumClusterwideEnvoyConfigPresent: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemNP,
			Help:      "Cilium Clusterwide Envoy Config are currently present in the agent",
			Name:      "cilium_clusterwide_envoy_config_present",
		}),

		ACLBVTEPEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "VTEP enabled on the agent",
			Name:      "vtep_enabled",
		}),

		ACLBBigTCPEnabled: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "Big TCP enabled on the agent",
			Name:      "big_tcp_enabled",
		}, metric.Labels{
			{Name: "protocol"},
		}),

		ACLBL2LBEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "L2 LB announcement enabled on the agent",
			Name:      "l2_lb_enabled",
		}),

		ACLBExternalEnvoyProxyEnabled: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "Envoy Proxy mode enabled on the agent",
			Name:      "envoy_proxy_enabled",
		}, metric.Labels{
			{Name: "mode"},
		}),

		ACLBCiliumNodeConfigEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "Cilium Node Config enabled on the agent",
			Name:      "cilium_node_config_enabled",
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
		if m.NPL3L4Ingested.Get() == 0 {
			m.NPL3L4Ingested.Inc()
		}
		m.NPL3L4Present.Inc()
	}
	if rf.Host {
		if m.NPHostNPIngested.Get() == 0 {
			m.NPHostNPIngested.Inc()
		}
		m.NPHostNPPresent.Inc()
	}
	if rf.DNS {
		if m.NPDNSIngested.Get() == 0 {
			m.NPDNSIngested.Inc()
		}
		m.NPDNSPresent.Inc()
	}
	if rf.HTTP {
		if m.NPHTTPIngested.Get() == 0 {
			m.NPHTTPIngested.Inc()
		}
		m.NPHTTPPresent.Inc()
	}
	if rf.OtherL7 {
		if m.NPOtherL7Ingested.Get() == 0 {
			m.NPOtherL7Ingested.Inc()
		}
		m.NPOtherL7Present.Inc()
	}
	if rf.Deny {
		if m.NPDenyPoliciesIngested.Get() == 0 {
			m.NPDenyPoliciesIngested.Inc()
		}
		m.NPDenyPoliciesPresent.Inc()
	}
	if rf.IngressCIDRGroup {
		if m.NPIngressCIDRGroupIngested.Get() == 0 {
			m.NPIngressCIDRGroupIngested.Inc()
		}
		m.NPIngressCIDRGroupPresent.Inc()
	}
	if rf.MutualAuth {
		if m.NPMutualAuthIngested.Get() == 0 {
			m.NPMutualAuthIngested.Inc()
		}
		m.NPMutualAuthPresent.Inc()
	}
	if rf.TLSInspection {
		if m.NPTLSInspectionIngested.Get() == 0 {
			m.NPTLSInspectionIngested.Inc()
		}
		m.NPTLSInspectionPresent.Inc()
	}
	if rf.SNIAllowList {
		if m.NPSNIAllowListIngested.Get() == 0 {
			m.NPSNIAllowListIngested.Inc()
		}
		m.NPSNIAllowListPresent.Inc()
	}
	if rf.HTTPHeaderMatches {
		if m.NPHTTPHeaderMatchesIngested.Get() == 0 {
			m.NPHTTPHeaderMatchesIngested.Inc()
		}
		m.NPHTTPHeaderMatchesPresent.Inc()
	}
	if rf.NonDefaultDeny {
		if m.NPNonDefaultDenyIngested.Get() == 0 {
			m.NPNonDefaultDenyIngested.Inc()
		}
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
		for _, cidrRuleSet := range i.IngressCommonRule.FromCIDRSet {
			if cidrRuleSet.CIDRGroupRef != "" {
				rf.IngressCIDRGroup = true
				rf.L3 = true
			}
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
				if p.Rules != nil && len(p.Rules.HTTP) > 0 {
					rf.HTTP = true
					if !rf.HTTPHeaderMatches {
						for _, httpRule := range p.Rules.HTTP {
							if len(httpRule.HeaderMatches) > 0 {
								rf.HTTPHeaderMatches = true
							}
						}
					}
				}
				if p.Rules != nil && (len(p.Rules.L7) > 0 || len(p.Rules.Kafka) > 0) {
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
					if p.Rules != nil && len(p.Rules.DNS) > 0 {
						rf.DNS = true
					}
					if p.Rules != nil && len(p.Rules.HTTP) > 0 {
						rf.HTTP = true
						if !rf.HTTPHeaderMatches {
							for _, httpRule := range p.Rules.HTTP {
								if len(httpRule.HeaderMatches) > 0 {
									rf.HTTPHeaderMatches = true
								}
							}
						}
					}
					if p.Rules != nil && (len(p.Rules.L7) > 0 || len(p.Rules.Kafka) > 0) {
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
	if m.NPLRPIngested.Get() == 0 {
		m.NPLRPIngested.Inc()
	}
	m.NPLRPPresent.Inc()
}

func (m Metrics) DelConfig(cfg *redirectpolicy.LRPConfig) {
	m.NPLRPPresent.Dec()
}

func (m Metrics) AddService(svc *k8s.Service) {
	if svc.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
		if m.ACLBInternalTrafficPolicyIngested.Get() == 0 {
			m.ACLBInternalTrafficPolicyIngested.Inc()
		}
		m.ACLBInternalTrafficPolicyPresent.Inc()
	}
}

func (m Metrics) DelService(svc *k8s.Service) {
	if svc.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
		m.ACLBInternalTrafficPolicyPresent.Dec()
	}
}

func (m Metrics) AddCEC(cec *v2.CiliumEnvoyConfigSpec) {
	if m.ACLBCiliumEnvoyConfigIngested.Get() == 0 {
		m.ACLBCiliumEnvoyConfigIngested.Inc()
	}
	m.ACLBCiliumEnvoyConfigPresent.Inc()
}

func (m Metrics) DelCEC(cec *v2.CiliumEnvoyConfigSpec) {
	m.ACLBCiliumEnvoyConfigPresent.Dec()
}

func (m Metrics) AddCCEC(cec *v2.CiliumEnvoyConfigSpec) {
	if m.ACLBCiliumClusterwideEnvoyConfigIngested.Get() == 0 {
		m.ACLBCiliumClusterwideEnvoyConfigIngested.Inc()
	}
	m.ACLBCiliumClusterwideEnvoyConfigPresent.Inc()
}

func (m Metrics) DelCCEC(cec *v2.CiliumEnvoyConfigSpec) {
	m.ACLBCiliumClusterwideEnvoyConfigPresent.Dec()
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

	m.DPMode.WithLabelValues(networkMode).Add(1)
	m.DPIPAM.WithLabelValues(ipamMode).Add(1)
	m.DPChaining.WithLabelValues(chainingMode).Add(1)
	m.DPIP.WithLabelValues(ip).Add(1)
	m.DPIdentityAllocation.WithLabelValues(identityAllocationMode).Add(1)
	m.DPDeviceMode.WithLabelValues(deviceMode).Add(1)

	if config.EnableCiliumEndpointSlice {
		m.DPCiliumEndpointSlicesEnabled.Add(1)
	}
	if config.EnableHostFirewall {
		m.NPHostFirewallEnabled.Add(1)
	}
	if config.EnableLocalRedirectPolicy {
		m.NPLocalRedirectPolicyEnabled.Add(1)
	}
	if params.MutualAuth.IsEnabled() {
		m.NPMutualAuthEnabled.Add(1)
	}
	for _, mode := range config.PolicyCIDRMatchMode {
		m.NPCIDRPoliciesToNodes.WithLabelValues(mode).Add(1)
	}
	if config.EnableIPSec {
		m.ACLBTransparentEncryption.WithLabelValues("ipsec", "false").Add(1)
	}
	if config.EnableWireguard {
		if config.EncryptNode {
			m.ACLBTransparentEncryption.WithLabelValues("wireguard", "true").Add(1)
		} else {
			m.ACLBTransparentEncryption.WithLabelValues("wireguard", "false").Add(1)
		}
	}

	if config.KubeProxyReplacement == option.KubeProxyReplacementTrue {
		m.ACLBKubeProxyReplacementEnabled.Add(1)
	}

	m.ACLBStandaloneNSLB.WithLabelValues(config.NodePortMode, config.NodePortAlg, config.NodePortAcceleration).Add(1)

	if config.BGPAnnouncePodCIDR || config.BGPAnnounceLBIP {
		m.ACLBBGPAdvertisementEnabled.Add(1)
	}

	if config.EnableIPv4EgressGateway {
		m.ACLBEgressGatewayEnabled.Add(1)
	}

	if params.BandwidthManager.Enabled() {
		m.ACLBBandwidthManagerEnabled.Add(1)
	}

	if config.EnableSRv6 {
		m.ACLBSRv6Enabled.Add(1)
	}

	if config.EnableSCTP {
		m.ACLBSCTPEnabled.Add(1)
	}

	if config.EnableInternalTrafficPolicy {
		m.ACLBInternalTrafficPolicyEnabled.Add(1)
	}

	if config.EnableEnvoyConfig {
		m.ACLBCiliumEnvoyConfigEnabled.Add(1)
	}

	if config.EnableVTEP {
		m.ACLBVTEPEnabled.Add(1)
	}

	ip = ""
	switch {
	case params.BigTCP.IsIPv4Enabled() && params.BigTCP.IsIPv6Enabled():
		ip = "ipv4-ipv6-dual-stack"
	case params.BigTCP.IsIPv4Enabled():
		ip = "ipv4-only"
	case params.BigTCP.IsIPv6Enabled():
		ip = "ipv6-only"
	}

	if ip != "" {
		m.ACLBBigTCPEnabled.WithLabelValues(ip).Add(1)
	}

	if config.EnableL2Announcements {
		m.ACLBL2LBEnabled.Add(1)
	}

	if config.ExternalEnvoyProxy {
		m.ACLBExternalEnvoyProxyEnabled.WithLabelValues("standalone").Add(1)
	} else {
		m.ACLBExternalEnvoyProxyEnabled.WithLabelValues("embedded").Add(1)
	}

	if params.DynamicConfigSource.IsNodeConfig() {
		m.ACLBCiliumNodeConfigEnabled.Add(1)
	}

	if config.EnableNonDefaultDenyPolicies {
		m.NPNonDefaultDenyEnabled.Add(1)
	}
}
