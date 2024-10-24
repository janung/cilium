// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"context"
	"fmt"

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
	// We depend on settings modified by the Daemon startup. Once the Deamon is initialized this promise
	// is resolved and we are guaranteed to have the correct settings.
	health.OK("Waiting for agent config")
	agentConfig, err := o.params.ConfigPromise.Await(ctx)
	if err != nil {
		return fmt.Errorf("failed to get agent config: %w", err)
	}

	o.params.Metrics.updateMetrics(o.params, agentConfig)

	return nil
}
