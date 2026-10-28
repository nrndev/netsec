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
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/nrndev/netsec/test/utils"
)

// TestE2E runs the specs on the local k3d-netsec cluster. `make test-e2e` builds
// the operator, loads it into the nodes and deploys it before this runs.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "netsec e2e suite")
}

var _ = BeforeSuite(func() {
	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(2 * time.Second)

	By("checking the operator is deployed on k3d-netsec")
	_, err := utils.Kubectl("-n", "netsec-system", "wait", "--for=condition=Available",
		"deployment/netsec-controller-manager", "--timeout=60s")
	Expect(err).NotTo(HaveOccurred(), "run the suite through `make test-e2e`")
})

// The operator's RBAC is narrow on purpose. A read that needs more (for example a
// cluster-wide watch of Jobs through the cache) only shows up as "forbidden" in its logs.
var _ = AfterSuite(func() {
	logs, err := utils.Kubectl("-n", "netsec-system", "logs", "deployment/netsec-controller-manager", "--tail=-1")
	Expect(err).NotTo(HaveOccurred())
	var forbidden []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(strings.ToLower(line), "forbidden") {
			forbidden = append(forbidden, line)
		}
	}
	Expect(forbidden).To(BeEmpty(), "the manager hit RBAC denials")
})
