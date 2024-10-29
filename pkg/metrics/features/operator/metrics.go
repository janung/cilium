// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	ACLBIPAMEnabled              metric.Counter
	ACLBIngressControllerEnabled metric.Counter
	ACLBGatewayAPIEnabled        metric.Counter
}

const (
	subsystemACLB = "_feature_adv_connect_and_lb"
)

func newMetrics() Metrics {
	return Metrics{
		ACLBIPAMEnabled: metric.NewCounter(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "LB IPAM enabled on the operator",
			Name:      "lb_ipam_enabled",
		}),

		ACLBIngressControllerEnabled: metric.NewCounter(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "IngressController enabled on the operator",
			Name:      "ingress_controller_enabled",
		}),

		ACLBGatewayAPIEnabled: metric.NewCounter(metric.CounterOpts{
			Namespace: metrics.Namespace + subsystemACLB,
			Help:      "GatewayAPI enabled on the operator",
			Name:      "gateway_api_enabled",
		}),
	}
}

type featureMetrics interface {
	updateMetrics(params featuresParams)
}

func (m Metrics) updateMetrics(params featuresParams) {
	if params.LBIPAM.IsEnabled() {
		m.ACLBIPAMEnabled.Add(1)
	}
	if params.IngressController.IsEnabled() {
		m.ACLBIngressControllerEnabled.Add(1)
	}
	if params.OperatorOpts.EnableGatewayAPI {
		m.ACLBGatewayAPIEnabled.Add(1)
	}
}
