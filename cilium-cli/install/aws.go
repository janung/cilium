// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

const (
	AwsNodeDaemonSetName              = "aws-node"
	AwsNodeDaemonSetNamespace         = "kube-system"
	AwsNodeDaemonSetNodeSelectorKey   = "io.cilium/aws-node-enabled"
	AwsNodeDaemonSetNodeSelectorValue = "true"
)

const (
	AwsNodeImageFamilyAmazonLinux2    = "AmazonLinux2"
	AwsNodeImageFamilyAmazonLinux2023 = "AmazonLinux2023"
	AwsNodeImageFamilyBottlerocket    = "Bottlerocket"
	AwsNodeImageFamilyCustom          = "Custom"
	AwsNodeImageFamilyUbuntu          = "Ubuntu"
	AwsNodeImageFamilyWindows         = "Windows"
)

type awsClusterInfo struct {
	ImageID string `json:"ImageID"`
}

type nodes struct {
	Items []node `json:"items"` 
}

type node struct {
	Status nodeStatus `json:"status"`
}

type nodeStatus struct {
	NodeInfo nodeInfo `json:"nodeInfo"`
}

type nodeInfo struct {
	OsImage string `json:"osImage"`
}

func (k *K8sInstaller) awsRetrieveNodeImageFamily() error {
	// setting default fallback value
	k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyCustom

//kubectl get node -o=jsonpath='{range.items[*]}{.status.nodeInfo.osImage}{"\n"}{end}'
	bytes, err := k.Exec("kubectl", "get", "node", "-o=json")
	if err != nil {
		k.Log("❌ Could not detect AWS node image family, defaulted to fallback value: %s", k.params.AWS.AwsNodeImageFamily)
		return err
	}

	nodeItems := nodes{}
	if err := json.Unmarshal(bytes, &nodeItems); err != nil {
		return fmt.Errorf("unable to unmarshal kubectl output: %w", err)
	}

	for _, item := range nodeItems.Items {
		k.Log("node image: %s", item.Status.NodeInfo.OsImage)
	}

	if len(nodeItems.Items) == 0 {
		k.Log("node image not found!")
		return fmt.Errorf("node image not found!!!")
	}

	ami := nodeItems.Items[0].Status.NodeInfo.OsImage
	switch {
	case "Amazon Linux 2" == ami:
		k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyAmazonLinux2
	case strings.Contains(ami, "Amazon Linux 2023"):
		k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyAmazonLinux2023
	case strings.Contains("BOTTLEROCKET", ami):
		k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyBottlerocket
	case strings.Contains("UBUNTU", ami):
		k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyUbuntu
	case strings.Contains("WINDOWS", ami):
		k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyWindows
	default:
		k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyCustom
	}

	k.Log("✅ Detected AWS node image family: %s", k.params.AWS.AwsNodeImageFamily)

	return nil
}

func getChainingMode(values map[string]interface{}) string {
	chainingMode, _, _ := unstructured.NestedString(values, "cni", "chainingMode")
	return chainingMode
}

func (k *K8sInstaller) awsSetupChainingMode(ctx context.Context, values map[string]interface{}) error {
	// detect chaining mode
	chainingMode := getChainingMode(values)

	// Do not stop AWS DS if we are running in chaining mode
	if chainingMode != "aws-cni" && !k.params.IsDryRun() {
		if _, err := k.client.GetDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, metav1.GetOptions{}); err == nil {
			k.Log("🔥 Patching the %q DaemonSet to evict its pods...", AwsNodeDaemonSetName)
			patch := []byte(fmt.Sprintf(`{"spec":{"template":{"spec":{"nodeSelector":{"%s":"%s"}}}}}`, AwsNodeDaemonSetNodeSelectorKey, AwsNodeDaemonSetNodeSelectorValue))
			if _, err := k.client.PatchDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
				k.Log("❌ Unable to patch the %q DaemonSet", AwsNodeDaemonSetName)
				return err
			}
		}
	}

	return nil
}

// Wrapper function forcing `eksctl` output to be in JSON for unmarshalling purposes
func (k *K8sInstaller) eksctlExec(args ...string) ([]byte, error) {
	args = append(args, "--output", "json")
	return k.Exec("eksctl", args...)
}
