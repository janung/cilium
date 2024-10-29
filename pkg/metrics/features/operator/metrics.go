// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	ACLBIPAMEnabled metric.Counter
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
	}
}

type featureMetrics interface {
	updateMetrics(params featuresParams)
}

func (m Metrics) updateMetrics(params featuresParams) {
	if params.LBIPAM.IsEnabled() {
		m.ACLBIPAMEnabled.Add(1)
	}
}
