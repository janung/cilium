// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

type orchestrator struct {
	params featuresParams
}

func newOrchestrator(params featuresParams) *orchestrator {
	o := &orchestrator{
		params: params,
	}
	group := params.JobRegistry.NewGroup(params.Health)
	group.Add(job.OneShot("reinitialize", o.reconciler, job.WithShutdown()))
	params.Lifecycle.Append(group)

	return o
}

func (o *orchestrator) reconciler(ctx context.Context, health cell.Health) error {
	o.params.Metrics.updateMetrics(o.params)

	return nil
}
