// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"encoding/json"
	"io"

	"github.com/cilium/cilium/api/v1/models"
)

func printPerNodeStatusJson(nodeMap map[string][]*models.Metric, w io.Writer) error {
	return json.NewEncoder(w).Encode(nodeMap)
}
