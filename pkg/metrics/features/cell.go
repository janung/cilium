// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"log/slog"

	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/redirectpolicy"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

const subsystem = "features"

// Cell is the cell for the Operator ClusterMesh
var Cell = cell.Module(
	"enabled-features",
	"Enabled features in cilium-agent",

	cell.Invoke(newOrchestrator),
	cell.Provide(
		func(m Metrics) featureMetrics {
			return m
		},
		func(m Metrics) api.PolicyMetrics {
			return m
		},
		func(m Metrics) redirectpolicy.LRPMetrics {
			return m
		},
		newOrchestrator,
	),
	metrics.Metric(newMetrics),
)

type featuresParams struct {
	cell.In

	Log           *slog.Logger
	JobRegistry   job.Registry
	Health        cell.Health
	Lifecycle     cell.Lifecycle
	ConfigPromise promise.Promise[*option.DaemonConfig]
	Metrics       featureMetrics

	TunnelConfig     tunnel.Config
	CNIConfigManager cni.CNIConfigManager
}
