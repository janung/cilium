// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"log/slog"

	operatorOption "github.com/cilium/cilium/operator/option"
	ciliumenvoyconfig2 "github.com/cilium/cilium/operator/pkg/ciliumenvoyconfig"
	"github.com/cilium/cilium/operator/pkg/ingress"
	"github.com/cilium/cilium/operator/pkg/lbipam"
	"github.com/cilium/cilium/operator/pkg/nodeipam"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

const subsystem = "features"

// Cell is the cell for the Operator ClusterMesh
var Cell = cell.Module(
	"enabled-features",
	"Enabled features in cilium-operator",

	cell.Invoke(newOrchestrator),
	cell.Provide(
		func(m Metrics) featureMetrics {
			return m
		},
		newOrchestrator,
	),
	metrics.Metric(newMetrics),
)

type featuresParams struct {
	cell.In

	Log         *slog.Logger
	JobRegistry job.Registry
	Health      cell.Health
	Lifecycle   cell.Lifecycle
	Metrics     featureMetrics

	LBIPAM            lbipam.Config
	IngressController ingress.IngressConfig
	LBConfig          ciliumenvoyconfig2.LoadBalancerConfig
	NodeIPAM          nodeipam.NodeIPAMConfig

	OperatorOpts *operatorOption.OperatorConfig
}
