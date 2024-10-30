// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/features"
	"github.com/cilium/cilium/cilium-cli/status"
)

func newCmdFeatures() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "features",
		Short:   "Cilium features",
		Long:    ``,
		Aliases: []string{"fs"},
	}
	cmd.AddCommand(newCmdFeaturesStatus())
	return cmd
}

func newCmdFeaturesStatus() *cobra.Command {
	params := features.Parameters{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display features status",
		Long:  "This command returns features status from all nodes in the cluster",
		RunE: func(_ *cobra.Command, _ []string) error {
			params.CiliumNamespace = namespace
			s := features.NewFeatures(k8sClient, params)
			if err := s.PrintFeatureStatus(context.Background()); err != nil {
				fatalf("Unable to print features status: %s", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&params.AgentPodSelector, "agent-pod-selector", defaults.AgentPodSelector, "Label on cilium-agent pods to select with")
	cmd.Flags().StringVar(&params.NodeName, "node", "", "Node from which features status will be fetched, omit to select all nodes")
	cmd.Flags().BoolVar(&params.PerNodeDetails, "per-node-details", false, "features status will be displayed for each cluster node separately")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 1*time.Minute, "Maximum time to wait for result, default 1 minute")
	cmd.Flags().StringVarP(&params.Output, "output", "o", status.OutputSummary, "Output format. One of: json, summary")
	return cmd
}
