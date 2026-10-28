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
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/nrndev/netsec/test/utils"
)

// The metrics endpoint is HTTPS and needs a token, and the operator's own NetworkPolicy
// only lets in namespaces labelled metrics=enabled. This scrapes it the way the
// kubebuilder scaffold documents: a ServiceAccount bound to metrics-reader, then curl.
var _ = Describe("metrics", Ordered, func() {
	const (
		ns  = "e2e-metrics"
		iso = "e2e-metrics-iso"
	)

	BeforeAll(func() {
		apply(namespaceYAML(ns, "e2e-metrics-a", "e2e-metrics-b"))
		kubectl("label", "namespace", ns, "metrics=enabled", "--overwrite")
		kubectl("-n", ns, "create", "serviceaccount", "metrics-e2e")
		kubectl("create", "clusterrolebinding", "e2e-metrics-reader",
			"--clusterrole=netsec-metrics-reader", "--serviceaccount="+ns+":metrics-e2e")
		// A long-lived pod: a brand-new pod cannot connect for its first seconds, while the
		// policy engine programs it, so a fresh pod per attempt would never get through.
		kubectl("-n", ns, "run", "curl-metrics", "--image="+nginxImage, "--image-pull-policy=IfNotPresent",
			"--restart=Never", "--command", "--", "sleep", "3600")
		kubectl("-n", ns, "wait", "--for=condition=Ready", "pod/curl-metrics", "--timeout=120s")
		apply(isolationYAML(iso, "e2e-metrics-a", "gateway", "e2e-metrics-b", "dashboard"))
	})

	AfterAll(func() {
		deleteCR("networkisolation", iso)
		_, _ = utils.Kubectl("delete", "clusterrolebinding", "e2e-metrics-reader", "--ignore-not-found")
		deleteNamespaces(ns, "e2e-metrics-a", "e2e-metrics-b")
	})

	It("serves the netsec metrics to a labelled namespace", func() {
		token := strings.TrimSpace(kubectl("-n", ns, "create", "token", "metrics-e2e", "--duration=10m"))
		scrape := func() (string, error) {
			return utils.Kubectl("-n", ns, "exec", "curl-metrics", "--", "curl", "-skf", "--max-time", "10",
				"-H", "Authorization: Bearer "+token,
				"https://netsec-controller-manager-metrics-service.netsec-system.svc:8443/metrics")
		}
		Eventually(scrape).Should(And(
			ContainSubstring("netsec_isolation_ready"),
			ContainSubstring("netsec_isolation_refusals_total"),
			ContainSubstring("netsec_hardening_workloads_total"),
			ContainSubstring(`netsec_isolation_ready{isolation="`+iso+`"} 1`),
		))
	})
})
