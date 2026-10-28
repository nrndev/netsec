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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/nrndev/netsec/test/utils"
)

const hardeningNS = "e2e-h"

func hardeningYAML(name, app, kind string, runAsNonRoot bool) string {
	return fmt.Sprintf(`apiVersion: netsec.nrnx.dev/v1alpha1
kind: WorkloadHardening
metadata: {name: %s}
spec:
  namespaces: [%s]
  workloadSelector: {matchLabels: {app: %s}}
  workloadKinds: [%s]
  strictSecurity: {runAsNonRoot: %t}
  rolloutTimeout: 1m
  action: Plan
`, name, hardeningNS, app, kind, runAsNonRoot)
}

func whField(name, path string) func() (string, error) {
	return func() (string, error) { return jsonpath([]string{"get", "workloadhardening", name}, path) }
}

// plan applies a Plan, waits for the hash and approves it with Apply.
func planAndApply(name, yaml string) {
	GinkgoHelper()
	apply(yaml)
	Eventually(whField(name, "{.status.phase}")).Should(Equal("Planned"))
	hash := kubectl("get", "workloadhardening", name, "-o", "jsonpath={.status.plan.hash}")
	Expect(hash).To(MatchRegexp(`^[0-9a-f]{16}$`))
	Expect(kubectl("get", "workloadhardening", name, "-o", "jsonpath={.status.plan.workloads[*].name}")).NotTo(BeEmpty(), "the plan must pick the workload")
	kubectl("patch", "workloadhardening", name, "--type=merge",
		"-p", fmt.Sprintf(`{"spec":{"action":"Apply","approvedPlanHash":"%s"}}`, hash))
}

func workloadState(name string) func() (string, error) {
	return whField(name, "{.status.plan.workloads[0].state}")
}

var _ = Describe("WorkloadHardening", Ordered, func() {
	BeforeAll(func() { apply(namespaceYAML(hardeningNS)) })

	AfterAll(func() {
		deleteCR("workloadhardening", "e2e-break", "e2e-safe", "e2e-sts", "e2e-del")
		deleteNamespaces(hardeningNS)
	})

	It("reverts a change that stops a root image from starting", func() {
		apply(workloadYAML(hardeningNS, "root-web", nginxImage, 80))
		kubectl("-n", hardeningNS, "wait", "--for=condition=Available", "deployment/root-web", "--timeout=120s")
		before := templateJSON("deployment", hardeningNS, "root-web")

		planAndApply("e2e-break", hardeningYAML("e2e-break", "root-web", "Deployment", true))

		Eventually(workloadState("e2e-break"), "3m").Should(Equal("Reverted"))
		Expect(whField("e2e-break", "{.status.plan.workloads[0].reason}")()).To(ContainSubstring("CreateContainerConfigError"))
		Expect(templateJSON("deployment", hardeningNS, "root-web")).To(Equal(before))
		kubectl("-n", hardeningNS, "wait", "--for=condition=Available", "deployment/root-web", "--timeout=120s")
		kubectl("-n", hardeningNS, "rollout", "status", "deployment/root-web", "--timeout=120s")
	})

	// Deleting a run must not drop the health gate: the failing rollout is still reverted.
	It("still reverts a failing rollout when the run is deleted mid-rollout", func() {
		apply(workloadYAML(hardeningNS, "del-web", nginxImage, 80))
		kubectl("-n", hardeningNS, "wait", "--for=condition=Available", "deployment/del-web", "--timeout=120s")
		before := templateJSON("deployment", hardeningNS, "del-web")

		planAndApply("e2e-del", hardeningYAML("e2e-del", "del-web", "Deployment", true))
		Eventually(workloadState("e2e-del"), "2m").Should(Equal("Applying"))
		kubectl("delete", "workloadhardening", "e2e-del", "--wait=false")

		Eventually(func() (string, error) {
			return utils.Kubectl("get", "workloadhardening", "e2e-del", "--ignore-not-found", "-o", "name")
		}, "3m").Should(BeEmpty(), "the run must go once the gate has finished")
		Expect(templateJSON("deployment", hardeningNS, "del-web")).To(Equal(before))
		kubectl("-n", hardeningNS, "wait", "--for=condition=Available", "deployment/del-web", "--timeout=120s")
		kubectl("-n", hardeningNS, "rollout", "status", "deployment/del-web", "--timeout=120s")
	})

	It("applies safe fields to a non-root image, then undoes exactly those", func() {
		apply(workloadYAML(hardeningNS, "safe-web", unprivilegedImage, 8080))
		kubectl("-n", hardeningNS, "wait", "--for=condition=Available", "deployment/safe-web", "--timeout=120s")
		before := templateJSON("deployment", hardeningNS, "safe-web")

		planAndApply("e2e-safe", hardeningYAML("e2e-safe", "safe-web", "Deployment", false))
		Eventually(workloadState("e2e-safe"), "3m").Should(Equal("Healthy"))

		get := func(path string) string {
			return kubectl("-n", hardeningNS, "get", "deployment", "safe-web", "-o", "jsonpath="+path)
		}
		Expect(get("{.spec.template.spec.securityContext.seccompProfile.type}")).To(Equal("RuntimeDefault"))
		Expect(get("{.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation}")).To(Equal("false"))
		Expect(get("{.spec.template.spec.containers[0].resources.requests.cpu}")).To(Equal("100m"))
		Expect(get("{.spec.template.spec.containers[0].resources.limits.memory}")).To(Equal("512Mi"))
		kubectl("-n", hardeningNS, "rollout", "status", "deployment/safe-web", "--timeout=120s")
		Expect(utils.PodByLabel(hardeningNS, "app=safe-web")).NotTo(BeZero())

		kubectl("patch", "workloadhardening", "e2e-safe", "--type=merge", "-p", `{"spec":{"action":"Undo"}}`)
		Eventually(whField("e2e-safe", "{.status.phase}"), "3m").Should(Equal("Undone"))
		Expect(templateJSON("deployment", hardeningNS, "safe-web")).To(Equal(before))
		kubectl("-n", hardeningNS, "rollout", "status", "deployment/safe-web", "--timeout=120s")
		Expect(utils.PodByLabel(hardeningNS, "app=safe-web")).NotTo(BeZero())
	})

	// A StatefulSet stuck on a bad revision does not roll forward on its own: the bad pod
	// must be deleted. A design that only reverts the template leaves it stuck.
	It("rolls a StatefulSet back, including its stuck pod", func() {
		apply(`apiVersion: apps/v1
kind: StatefulSet
metadata: {name: root-sts, namespace: ` + hardeningNS + `, labels: {app: root-sts}}
spec:
  serviceName: root-sts
  replicas: 2
  selector: {matchLabels: {app: root-sts}}
  template:
    metadata: {labels: {app: root-sts}}
    spec:
      containers:
      - name: web
        image: ` + nginxImage + `
        imagePullPolicy: Never
        ports: [{name: http, containerPort: 80}]
        readinessProbe: {httpGet: {path: /, port: http}}
`)
		sts := func(path string) func() (string, error) {
			return func() (string, error) {
				return jsonpath([]string{"-n", hardeningNS, "get", "statefulset", "root-sts"}, path)
			}
		}
		Eventually(sts("{.status.readyReplicas}"), "3m").Should(Equal("2"))

		planAndApply("e2e-sts", hardeningYAML("e2e-sts", "root-sts", "StatefulSet", true))
		Eventually(workloadState("e2e-sts"), "3m").Should(Equal("Reverted"))

		Eventually(sts("{.status.readyReplicas}"), "3m").Should(Equal("2"))
		Eventually(func() (bool, error) {
			cur, err := sts("{.status.currentRevision}")()
			if err != nil {
				return false, err
			}
			upd, err := sts("{.status.updateRevision}")()
			return cur == upd, err
		}, "3m").Should(BeTrue())
	})
})
