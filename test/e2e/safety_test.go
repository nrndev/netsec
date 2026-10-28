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
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/nrndev/netsec/test/utils"
)

const operatorSA = "system:serviceaccount:netsec-system:netsec-controller-manager"

// S3: isolation fails closed. With the operator stopped, the policies it made keep blocking.
var _ = Describe("operator down", Ordered, func() {
	const iso = "e2e-s3"
	nsAll := []string{"e2e-s3a", "e2e-s3b"}

	BeforeAll(func() {
		apply(namespaceYAML(nsAll...))
		apply(workloadYAML("e2e-s3a", "gateway", nginxImage, 80) + workloadYAML("e2e-s3b", "dashboard", nginxImage, 80))
		for _, ns := range nsAll {
			kubectl("-n", ns, "wait", "--for=condition=Available", "deployment", "--all", "--timeout=120s")
		}
	})

	// restoreOperator starts the operator again. Safe to call twice. It is not a DeferCleanup:
	// in an Ordered container that would run after AfterAll, which needs the operator.
	restoreOperator := func() {
		kubectl("-n", "netsec-system", "scale", "deployment/netsec-controller-manager", "--replicas=1")
		kubectl("-n", "netsec-system", "wait", "--for=condition=Available", "deployment/netsec-controller-manager", "--timeout=120s")
	}

	AfterAll(func() {
		restoreOperator()
		// Deleting the isolation needs the operator's finalizer, so this also proves it is back.
		// The operator may still be waiting for the leader lease, which can take longer than one
		// kubectl call is allowed to, so poll instead of using one blocking delete.
		kubectl("delete", "networkisolation", iso, "--ignore-not-found", "--wait=false")
		Eventually(func() (string, error) {
			return utils.Kubectl("get", "networkisolation", iso, "--ignore-not-found", "-o", "name")
		}).Should(BeEmpty(), "the operator must come back and finish the delete")
		deleteNamespaces(nsAll...)
	})

	It("keeps blocking while the operator is stopped", func() {
		apply(isolationYAML(iso, "e2e-s3a", "gateway", "e2e-s3b", "dashboard"))
		waitReady(iso)
		gw, err := utils.PodByLabel("e2e-s3a", "app=gateway")
		Expect(err).NotTo(HaveOccurred())
		dash, err := utils.PodByLabel("e2e-s3b", "app=dashboard")
		Expect(err).NotTo(HaveOccurred())
		probes := []utils.Probe{
			{Name: "gw→dash ip", From: gw, URL: "http://" + dash.IP + "/"},
			{Name: "gw→dash svc", From: gw, URL: "http://dashboard.e2e-s3b/"},
			{Name: "dash→gw ip", From: dash, URL: "http://" + gw.IP + "/"},
		}
		Eventually(func() ([]string, error) {
			res, err := utils.RunMatrix(probes)
			return utils.Mismatches(res), err
		}).Should(BeEmpty(), "blocked before the operator stops")

		// Structured logs (US10): the operator's lines carry the isolation's name as a key.
		logs := kubectl("-n", "netsec-system", "logs", "deployment/netsec-controller-manager", "--tail=-1")
		// At least one line must parse as JSON (none do in console mode), and one must name the isolation.
		parsed, named := 0, false
		for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
			var entry map[string]any
			if json.Unmarshal([]byte(line), &entry) != nil {
				continue
			}
			parsed++
			if entry["controller"] == "networkisolation" && entry["name"] == iso {
				named = true
			}
		}
		Expect(parsed).To(BeNumerically(">", 0), "operator logs are JSON lines")
		Expect(named).To(BeTrue(), "an operator log line names the isolation")

		kubectl("-n", "netsec-system", "scale", "deployment/netsec-controller-manager", "--replicas=0")
		kubectl("-n", "netsec-system", "wait", "--for=delete", "pod", "-l", "control-plane=controller-manager", "--timeout=120s")

		// Every probe is sent after the operator is gone. Run twice so a slow rule update cannot hide a leak.
		for range 2 {
			res, err := utils.RunMatrix(probes)
			Expect(err).NotTo(HaveOccurred())
			Expect(utils.Mismatches(res)).To(BeEmpty(), "isolation must hold with the operator down")
		}
		Expect(netsecPolicies("e2e-s3a", "e2e-s3b")).To(HaveLen(2), "our policies are still there")
		restoreOperator()
	})
})

// S6: the operator runs with a restricted security context and narrow RBAC, and only admins
// can create its objects.
var _ = Describe("least privilege", func() {
	// canI asks the API server whether the user may do verb on resource. kubectl exits 1 for
	// "no", so the exit code is ignored and the answer read from the output.
	canI := func(as, verb, resource string) bool {
		args := []string{"auth", "can-i", verb, resource, "--all-namespaces"}
		if as != "" {
			args = append(args, "--as="+as)
		}
		out, _ := utils.Kubectl(args...)
		return strings.TrimSpace(out) == "yes"
	}

	It("runs the operator as non-root, read-only, with no capabilities and no privilege escalation", func() {
		get := func(path string) string {
			return kubectl("-n", "netsec-system", "get", "deployment/netsec-controller-manager", "-o", "jsonpath="+path)
		}
		Expect(get("{.spec.template.spec.securityContext.runAsNonRoot}")).To(Equal("true"))
		Expect(get("{.spec.template.spec.securityContext.seccompProfile.type}")).To(Equal("RuntimeDefault"))
		Expect(get("{.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem}")).To(Equal("true"))
		Expect(get("{.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation}")).To(Equal("false"))
		Expect(get("{.spec.template.spec.containers[0].securityContext.capabilities.drop}")).To(Equal(`["ALL"]`))
	})

	It("gives the operator only the access it needs", func() {
		// Controls first: the operator may do what it is for, so a "no" below is not a broken check.
		for _, ok := range [][2]string{{"patch", "deployments.apps"}, {"create", "networkpolicies.networking.k8s.io"}, {"delete", "pods"}} {
			Expect(canI(operatorSA, ok[0], ok[1])).To(BeTrue(), "%s %s", ok[0], ok[1])
		}
		for _, no := range [][2]string{
			{"get", "secrets"}, {"list", "secrets"}, {"create", "deployments.apps"}, {"delete", "deployments.apps"},
			{"patch", "jobs.batch"}, {"patch", "pods"}, {"create", "pods"}, {"delete", "namespaces"},
			{"create", "clusterroles.rbac.authorization.k8s.io"}, {"*", "*"},
		} {
			Expect(canI(operatorSA, no[0], no[1])).To(BeFalse(), "%s %s must be refused", no[0], no[1])
		}
	})

	It("lets only admins create NetSec objects", func() {
		for _, res := range []string{"networkisolations.netsec.nrnx.dev", "workloadhardenings.netsec.nrnx.dev"} {
			Expect(canI("", "create", res)).To(BeTrue(), "the cluster admin can create %s", res)
			Expect(canI("system:serviceaccount:default:default", "create", res)).To(BeFalse(), "an ordinary service account must not create %s", res)
			Expect(canI("system:serviceaccount:default:default", "patch", res)).To(BeFalse())
		}
	})
})
