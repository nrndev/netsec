//go:build e2e

/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"encoding/json"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"

	. "github.com/onsi/gomega"

	"github.com/nrndev/netsec/test/utils"
)

const (
	nginxImage        = "nginx:1.31.6-alpine"                       // runs as root, listens on 80
	unprivilegedImage = "nginxinc/nginx-unprivileged:1.31.6-alpine" // non-root, listens on 8080
)

// kubectl runs a kubectl command that must succeed and returns its output.
func kubectl(args ...string) string {
	GinkgoHelper()
	out, err := utils.Kubectl(args...)
	Expect(err).NotTo(HaveOccurred())
	return out
}

func apply(yaml string) {
	GinkgoHelper()
	Expect(utils.Apply(yaml)).To(Succeed())
}

// namespaceYAML makes the objects for namespaces, so every spec group owns its namespaces.
func namespaceYAML(names ...string) string {
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "---\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n", n)
	}
	return b.String()
}

// workloadYAML is a one-replica Deployment labelled app=name and a Service on port 80.
func workloadYAML(ns, name, image string, port int) string {
	return fmt.Sprintf(`---
apiVersion: apps/v1
kind: Deployment
metadata: {name: %[2]s, namespace: %[1]s, labels: {app: %[2]s}}
spec:
  selector: {matchLabels: {app: %[2]s}}
  template:
    metadata: {labels: {app: %[2]s}}
    spec:
      containers:
      - name: %[2]s
        image: %[3]s
        imagePullPolicy: Never # loaded by make k3d-load-test-images; a missing image fails fast
        ports: [{name: http, containerPort: %[4]d}]
        readinessProbe: {httpGet: {path: /, port: http}}
---
apiVersion: v1
kind: Service
metadata: {name: %[2]s, namespace: %[1]s}
spec:
  selector: {app: %[2]s}
  ports: [{name: http, port: 80, targetPort: http}]
`, ns, name, image, port)
}

// deleteNamespaces removes test namespaces and waits for them to be gone.
func deleteNamespaces(names ...string) {
	args := append([]string{"delete", "namespace", "--ignore-not-found", "--wait", "--timeout=120s"}, names...)
	_, err := utils.Kubectl(args...)
	Expect(err).NotTo(HaveOccurred())
}

// deleteCR removes cluster-scoped custom resources; the operator's finalizer cleans up.
func deleteCR(kind string, names ...string) {
	args := append([]string{"delete", kind, "--ignore-not-found", "--wait", "--timeout=120s"}, names...)
	_, err := utils.Kubectl(args...)
	Expect(err).NotTo(HaveOccurred())
}

// jsonpath reads one field. The result is empty when the field is not set.
func jsonpath(args []string, path string) (string, error) {
	return utils.Kubectl(append(args, "-o", "jsonpath="+path)...)
}

// templateJSON returns .spec.template of a workload, to compare before and after hardening.
func templateJSON(kind, ns, name string) string {
	GinkgoHelper()
	out := kubectl("-n", ns, "get", kind, name, "-o", "jsonpath={.spec.template}")
	var v any
	Expect(json.Unmarshal([]byte(out), &v)).To(Succeed())
	b, err := json.Marshal(v) // json sorts map keys, so equal templates give equal strings
	Expect(err).NotTo(HaveOccurred())
	return string(b)
}
