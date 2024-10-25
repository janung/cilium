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

	NPL3L4Ingested             metric.Gauge
	NPL3L4Present              metric.Gauge
	NPCCNPIngested             metric.Gauge
	NPCCNPPresent              metric.Gauge
	NPHostNPIngested           metric.Gauge
	NPHostNPPresent            metric.Gauge
	NPDNSIngested              metric.Gauge
	NPDNSPresent               metric.Gauge
	NPHTTPIngested             metric.Gauge
	NPHTTPPresent              metric.Gauge
	NPOtherL7Ingested          metric.Gauge
	NPOtherL7Present           metric.Gauge
	NPLRPIngested              metric.Gauge
	NPLRPPresent               metric.Gauge
	NPDenyPoliciesIngested     metric.Gauge
	NPDenyPoliciesPresent      metric.Gauge
	NPIngressCIDRGroupIngested metric.Gauge
	NPIngressCIDRGroupPresent  metric.Gauge
}

const (
	subsystemDP = "_feature_datapath"
	subsystemNP = "_feature_network_policies"
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
	}
}

type featureMetrics interface {
	updateMetrics(params featuresParams, config *option.DaemonConfig)
}

func (m Metrics) AddRule(r api.Rule) {
	isL3, isHost, isDNS, isHTTP, isOtherL7, isDeny, isIngressCIDRGroup := ruleType(r)

	if isL3 {
		m.NPL3L4Ingested.Set(1)
		m.NPL3L4Present.Inc()
	}
	if isHost {
		m.NPHostNPIngested.Set(1)
		m.NPHostNPPresent.Inc()
	}
	if isDNS {
		m.NPDNSIngested.Set(1)
		m.NPDNSPresent.Inc()
	}
	if isHTTP {
		m.NPHTTPIngested.Set(1)
		m.NPHTTPPresent.Inc()
	}
	if isOtherL7 {
		m.NPOtherL7Ingested.Set(1)
		m.NPOtherL7Present.Inc()
	}
	if isDeny {
		m.NPDenyPoliciesIngested.Set(1)
		m.NPDenyPoliciesPresent.Inc()
	}
	if isIngressCIDRGroup {
		m.NPIngressCIDRGroupIngested.Set(1)
		m.NPIngressCIDRGroupPresent.Inc()
	}
}

func ruleType(r api.Rule) (isL3, isHost, isDNS, isHTTP, isOtherL7, isDeny, isIngressCIDRGroup bool) {
	for _, i := range r.Ingress {
		if len(i.IngressCommonRule.FromNodes) > 0 {
			isHost = true
			isL3 = true
		}
		if !isL3 && i.IngressCommonRule.IsL3() {
			isL3 = true
		}
		if isL3 && isHost {
			break
		}
	}

	if !isL3 || !isHost {
		for _, i := range r.IngressDeny {
			isDeny = true
			if len(i.IngressCommonRule.FromNodes) > 0 {
				isHost = true
				isL3 = true
			}
			for _, cidrRuleSet := range i.IngressCommonRule.FromCIDRSet {
				if cidrRuleSet.CIDRGroupRef != "" {
					isIngressCIDRGroup = true
					isL3 = true
				}
			}
			if !isL3 && i.IngressCommonRule.IsL3() {
				isL3 = true
			}
			if isL3 && isHost && isDeny {
				break
			}
		}
	}

	if !isL3 || !isHost {
		for _, e := range r.Egress {
			if len(e.EgressCommonRule.ToNodes) > 0 {
				isHost = true
				isL3 = true
			}

			if !isL3 && e.EgressCommonRule.IsL3() {
				isL3 = true
			}

			if !isDNS || !isHTTP || !isOtherL7 {
				if len(e.ToFQDNs) > 0 {
					isDNS = true
				}
				for _, p := range e.ToPorts {
					if len(p.Rules.DNS) > 0 {
						isDNS = true
					}
					if len(p.Rules.HTTP) > 0 {
						isHTTP = true
					}
					if len(p.Rules.L7) > 0 || len(p.Rules.Kafka) > 0 {
						isOtherL7 = true
					}
					if isDNS && isHTTP && isOtherL7 {
						break
					}
				}
			}

			if isL3 && isHost && isDNS && isHTTP && isOtherL7 {
				break
			}
		}
	}

	if !isL3 || !isHost || !isDeny {
		for _, e := range r.EgressDeny {
			isDeny = true
			if len(e.EgressCommonRule.ToNodes) > 0 {
				isHost = true
				isL3 = true
			}

			if !isL3 && e.EgressCommonRule.IsL3() {
				isL3 = true
			}

			if isL3 && isHost && isDeny {
				break
			}
		}
	}
	return
}

func (m Metrics) DelRule(r api.Rule) {
	isL3, isHost, isDNS, isHTTP, isOtherL7, isDeny, isIngressCIDRGroup := ruleType(r)

	if isL3 {
		m.NPL3L4Present.Dec()
	}
	if isHost {
		m.NPHostNPPresent.Dec()
	}
	if isDNS {
		m.NPDNSPresent.Dec()
	}
	if isHTTP {
		m.NPHTTPPresent.Dec()
	}
	if isOtherL7 {
		m.NPOtherL7Present.Dec()
	}
	if isDeny {
		m.NPDenyPoliciesPresent.Dec()
	}
	if isIngressCIDRGroup {
		m.NPIngressCIDRGroupPresent.Dec()
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
}
