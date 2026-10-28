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

package controller

import (
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netsecv1alpha1 "github.com/nrndev/netsec/api/v1alpha1"
	"github.com/nrndev/netsec/internal/hardening"
)

// claim is the guarantee that two runs never patch one workload. This drives it directly,
// with no manager running, so it fails if the Lease is removed: the spec that races two
// whole runs can pass without it.
var _ = Describe("workload claim", func() {
	It("gives a workload to exactly one of two runs and tells the other who holds it", func() {
		const ns, workload = "claim-direct", "web"
		w := netsecv1alpha1.PlannedWorkload{Kind: netsecv1alpha1.KindDeployment, Namespace: ns, Name: workload, State: netsecv1alpha1.StatePending}
		// Two runs that are both rolling the workload, so neither claim is stale.
		runs := make([]*netsecv1alpha1.WorkloadHardening, 2)
		for i, name := range []string{"claim-run-a", "claim-run-b"} {
			run := &netsecv1alpha1.WorkloadHardening{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       netsecv1alpha1.WorkloadHardeningSpec{Namespaces: []string{ns}},
			}
			Expect(k8sClient.Create(ctx, run)).To(Succeed())
			run.Status.Phase = netsecv1alpha1.PhaseApplying
			run.Status.Plan = &netsecv1alpha1.HardeningPlan{Hash: "0123456789abcdef", Workloads: []netsecv1alpha1.PlannedWorkload{w}}
			Expect(k8sClient.Status().Update(ctx, run)).To(Succeed())
			runs[i] = run
		}
		lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: claimNS, Name: hardening.ClaimName(w.Kind, ns, workload)}}
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, lease))).To(Succeed())
			for _, run := range runs {
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, run))).To(Succeed())
			}
		})

		r := &WorkloadHardeningReconciler{Client: k8sClient, APIReader: k8sClient, Namespace: claimNS}
		holders := make([]string, 2)
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range runs {
			wg.Go(func() {
				defer GinkgoRecover()
				holders[i], errs[i] = (&pass{r: r, wh: runs[i]}).claim(ctx, w)
			})
		}
		wg.Wait()
		Expect(errs).To(Equal([]error{nil, nil}))

		won := 0
		for i, h := range holders {
			if h == "" {
				won++
				continue
			}
			Expect(h).To(Equal(runs[1-i].Name), "the loser is told the winner's name")
		}
		Expect(won).To(Equal(1), "exactly one run gets the claim: %v", holders)
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(lease), lease)).To(Succeed())
	})
})
