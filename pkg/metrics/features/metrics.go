// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"fmt"

	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
)

type Metrics struct {
	DPMode                 metric.Vec[metric.Gauge]
	DPIPAM                 metric.Vec[metric.Gauge]
	DPChaining             metric.Vec[metric.Gauge]
	DPIP                   metric.Vec[metric.Gauge]
	DPIdentityAllocation   metric.Vec[metric.Gauge]
	DPCiliumEndpointSlices metric.Vec[metric.Gauge]
	DPDeviceMode           metric.Vec[metric.Gauge]
}

const (
	subsystemDP = "_feature_datapath"
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

		DPCiliumEndpointSlices: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace + subsystemDP,
			Help:      "Cilium Endpoint Slices enabled on the agent",
			Name:      "cilium_endpoint_slices",
		}, metric.Labels{
			{Name: "enabled", Values: metric.NewValues("true", "false")},
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
	}
}

type featureMetrics interface {
	updateMetrics(params featuresParams, config *option.DaemonConfig)
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

	ciliumEndpointSlicesEnabled := fmt.Sprintf("%t", config.EnableCiliumEndpointSlice)

	deviceMode := config.DatapathMode

	m.DPMode.WithLabelValues(networkMode).Set(1)
	m.DPIPAM.WithLabelValues(ipamMode).Set(1)
	m.DPChaining.WithLabelValues(chainingMode).Set(1)
	m.DPIP.WithLabelValues(ip).Set(1)
	m.DPIdentityAllocation.WithLabelValues(identityAllocationMode).Set(1)
	m.DPCiliumEndpointSlices.WithLabelValues(ciliumEndpointSlicesEnabled).Set(1)
	m.DPDeviceMode.WithLabelValues(deviceMode).Set(1)
}
