// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/defaults"
	corev1 "k8s.io/api/core/v1"
)

// PrintFeatureStatus prints encryption status from all/specific cilium agent pods.
func (s *Feature) PrintFeatureStatus(ctx context.Context) error {
	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	pods, err := s.fetchCiliumPods(ctx)
	if err != nil {
		return err
	}

	nodeMap, err := s.fetchStatusConcurrently(ctx, pods)
	if err != nil {
		return err
	}

	return printPerNodeStatusMk(nodeMap, s.params.Output)
	// return printPerNodeStatusTabWriter(nodeMap, s.params.Output)
}

func (s *Feature) fetchStatusConcurrently(ctx context.Context, pods []corev1.Pod) (map[string][]*models.Metric, error) {
	// res contains data returned from cilium pod
	type res struct {
		nodeName string
		status   []*models.Metric
		err      error
	}
	resCh := make(chan res)
	defer close(resCh)

	// concurrently fetch state from each cilium pod
	for _, pod := range pods {
		go func(ctx context.Context, pod corev1.Pod) {
			st, err := s.fetchMetricsFromPod(ctx, pod)
			resCh <- res{
				nodeName: pod.Spec.NodeName,
				status:   st,
				err:      err,
			}
		}(ctx, pod)
	}

	// read from the channel, on error, store error and continue to next node
	var err error
	data := make(map[string][]*models.Metric)
	for range pods {
		r := <-resCh
		if r.err != nil {
			err = errors.Join(err, r.err)
			continue
		}
		data[r.nodeName] = r.status
	}
	return data, err
}

func (s *Feature) fetchMetricsFromPod(ctx context.Context, pod corev1.Pod) ([]*models.Metric, error) {
	cmd := []string{"cilium", "metrics", "list", "-o", "json"}
	output, err := s.client.ExecInPod(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		return []*models.Metric{}, fmt.Errorf("failed to features status from %s: %w", pod.Name, err)
	}
	encStatus, err := nodeStatusFromOutput(output.String())
	if err != nil {
		return []*models.Metric{}, fmt.Errorf("failed to features status from %s: %w", pod.Name, err)
	}
	return encStatus, nil
}

func nodeStatusFromOutput(output string) ([]*models.Metric, error) {
	var encStatus []*models.Metric
	if err := json.Unmarshal([]byte(output), &encStatus); err != nil {
		return []*models.Metric{}, fmt.Errorf("failed to unmarshal json: %w", err)
	}
	return encStatus, nil
}

func stringIndex(s, substr string) int {
	for i := range s {
		if len(s) >= i+len(substr) && s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func printPerNodeStatusTabWriter(nodeMap map[string][]*models.Metric, format string) error {
	var nodesSorted []string
	for node := range nodeMap {
		nodesSorted = append(nodesSorted, node)
	}
	slices.Sort(nodesSorted)

	// Initialize tabwriter for formatted output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Header row
	fmt.Fprintf(w, "Uniform\tName\tLabels\t")
	for _, node := range nodesSorted {
		fmt.Fprintf(w, "%s\t", node)
	}
	fmt.Fprintf(w, "\n")

	// Parse data and organize it by name and labels
	result := make(map[string]map[string]float64)
	allNames := map[string]struct{}{}
	for nodeName, jsonData := range nodeMap {
		for _, d := range jsonData {
			// Generate a unique key based on name and labels for each entry
			key := d.Name
			if !strings.Contains(key, "feature") {
				continue
			}
			var orderdLabels []string
			for k, v := range d.Labels {
				orderdLabels = append(orderdLabels, fmt.Sprintf("%s=%s", k, v))
			}
			slices.Sort(orderdLabels)
			if len(orderdLabels) != 0 {
				key += ";"
			}
			key += strings.Join(orderdLabels, ";")

			if _, ok := result[key]; !ok {
				result[key] = make(map[string]float64)
			}
			result[key][nodeName] = d.Value
			allNames[key] = struct{}{}
		}
	}

	var allNamesSorted []string
	for key := range allNames {
		allNamesSorted = append(allNamesSorted, key)
	}
	slices.Sort(allNamesSorted)
	for _, key := range allNamesSorted {
		name, labels := parseNameAndLabels(key)

		allValues := make(map[float64]struct{})
		nonBinary := false
		for _, node := range nodesSorted {
			value := result[key][node]
			allValues[value] = struct{}{}
			if value != 0 && value != 1 {
				nonBinary = true
			}
		}

		// Determine if "X" should be placed in "Overall" column
		if len(allValues) > 1 && !nonBinary {
			fmt.Fprintf(w, "X\t")
		} else {
			fmt.Fprintf(w, "\t")
		}

		fmt.Fprintf(w, "%s\t%s\t", name, labels)
		for _, node := range nodesSorted {
			value := result[key][node]
			fmt.Fprintf(w, "%.0f\t", value)
		}
		fmt.Fprintln(w)
	}

	// Flush the writer to output all buffered data
	return w.Flush()
}

func printPerNodeStatusMk(nodeMap map[string][]*models.Metric, format string) error {
	var nodesSorted []string
	for node := range nodeMap {
		nodesSorted = append(nodesSorted, node)
	}
	slices.Sort(nodesSorted)

	builder := strings.Builder{}
	builder.WriteString(fmt.Sprintf("| Uniform |"))
	builder.WriteString(fmt.Sprintf(" Name                             | Labels                      |"))
	for _, node := range nodesSorted {
		builder.WriteString(fmt.Sprintf(" %s |", node))
	}
	builder.WriteString(fmt.Sprintln())
	builder.WriteString(fmt.Sprint("|----------------------------------|-----------------------------|"))
	for range nodeMap {
		builder.WriteString(fmt.Sprint("-------|"))
	}
	builder.WriteString(fmt.Sprintf("---------|\n"))

	// Parse data and organize it by name and labels
	result := make(map[string]map[string]float64)
	allNames := map[string]struct{}{}
	for nodeName, metricsData := range nodeMap {
		for _, d := range metricsData {
			// Generate a unique key based on name and labels for each entry
			key := d.Name
			if !strings.Contains(key, "feature") {
				continue
			}
			var orderdLabels []string
			for k, v := range d.Labels {
				orderdLabels = append(orderdLabels, fmt.Sprintf("%s=%s", k, v))
			}
			slices.Sort(orderdLabels)
			if len(orderdLabels) != 0 {
				key += ";"
			}
			key += strings.Join(orderdLabels, ";")

			if _, ok := result[key]; !ok {
				result[key] = make(map[string]float64)
			}
			result[key][nodeName] = d.Value
			allNames[key] = struct{}{}
		}
	}

	var allNamesSorted []string
	for key := range allNames {
		allNamesSorted = append(allNamesSorted, key)
	}
	slices.Sort(allNamesSorted)
	for _, key := range allNamesSorted {
		allValues := make(map[float64]struct{})
		nonBinary := false

		for _, node := range nodesSorted {
			value := result[key][node]
			allValues[value] = struct{}{}
			if value != 0 && value != 1 {
				nonBinary = true
			}
		}

		if len(allValues) > 1 && !nonBinary {
			builder.WriteString(fmt.Sprintf("|    :warning:    "))
		} else {
			builder.WriteString(fmt.Sprintf("|    :heavy_check_mark:   "))
		}
		name, labels := parseNameAndLabels(key)
		builder.WriteString(fmt.Sprintf("| %-32s | %-27s |", name, labels))

		for _, node := range nodesSorted {
			value := result[key][node]
			builder.WriteString(fmt.Sprintf(" %-5.0f |", value))
		}
		builder.WriteString(fmt.Sprintln())
	}
	_, err := fmt.Println(builder.String())
	return err
}

// parseNameAndLabels splits the key into name and labels based on the first ";" separator
func parseNameAndLabels(key string) (string, string) {
	if idx := stringIndex(key, ";"); idx != -1 {
		return key[:idx], key[idx+1:]
	}
	return key, "" // No labels found, return an empty labels string
}
