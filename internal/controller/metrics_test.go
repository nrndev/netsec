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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	netsecv1alpha1 "github.com/nrndev/netsec/api/v1alpha1"
)

// counter reads one series of a counter. Series are process-wide, so specs compare
// against a value they read first.
func counter(vec *prometheus.CounterVec, label string) float64 {
	return testutil.ToFloat64(vec.WithLabelValues(label))
}

// reconciles returns how many reconciles the named controller has finished.
// Specs wait for it to grow, instead of sleeping, to know a reconcile ran.
func reconciles(controller string) float64 {
	GinkgoHelper()
	families, err := metrics.Registry.Gather()
	Expect(err).NotTo(HaveOccurred())
	var total float64
	for _, f := range families {
		if f.GetName() != "controller_runtime_reconcile_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "controller" && l.GetValue() == controller {
					total += m.GetCounter().GetValue()
				}
			}
		}
	}
	return total
}

// readyGauge gathers the netsec_isolation_ready series of one isolation. ok is false when
// there is none. It reads the registry and never calls WithLabelValues, which would
// create the series and make every absence check pass or fail on its own doing.
func readyGauge(isolation string) (value float64, ok bool) {
	GinkgoHelper()
	families, err := metrics.Registry.Gather()
	Expect(err).NotTo(HaveOccurred())
	for _, f := range families {
		if f.GetName() != "netsec_isolation_ready" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetValue() == isolation {
					return m.GetGauge().GetValue(), true
				}
			}
		}
	}
	return 0, false
}

func hasReadySeries(isolation string) bool {
	GinkgoHelper()
	_, ok := readyGauge(isolation)
	return ok
}

func readyValue(isolation string) func() float64 {
	return func() float64 {
		v, _ := readyGauge(isolation)
		return v
	}
}

func waitReconcile(controller string, after float64) {
	GinkgoHelper()
	Eventually(func() float64 { return reconciles(controller) }, 20*time.Second, 50*time.Millisecond).Should(BeNumerically(">", after))
}

var _ = Describe("metrics", func() {
	It("counts a refusal and a Ready gauge once per change, not once per reconcile", func() {
		SetDefaultEventuallyTimeout(20 * time.Second)
		SetDefaultEventuallyPollingInterval(100 * time.Millisecond)
		nsA, nsB, name := "met-a", "met-b", "iso-metrics"
		createNS(nsA)
		createNS(nsB)
		// No node reports a pod range, so the isolation is refused.
		Expect(k8sClient.DeleteAllOf(ctx, &corev1.Node{})).To(Succeed())
		stop := startManager(nil)
		defer stop()
		before := counter(isolationRefusals, "PodCIDRUnknown")
		Expect(hasReadySeries(name)).To(BeFalse(), "no series before the isolation exists")

		iso := &netsecv1alpha1.NetworkIsolation{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: netsecv1alpha1.NetworkIsolationSpec{
				Between: []netsecv1alpha1.PodGroup{
					{Name: gatewayApp, Namespaces: []string{nsA}, PodSelector: labelSel(appLabel, gatewayApp)},
					{Name: dashboardApp, Namespaces: []string{nsB}, PodSelector: labelSel(appLabel, dashboardApp)},
				},
			},
		}
		Expect(k8sClient.Create(ctx, iso)).To(Succeed())
		Eventually(func() float64 { return counter(isolationRefusals, "PodCIDRUnknown") }).Should(Equal(before + 1))
		Eventually(func() bool { return hasReadySeries(name) }).Should(BeTrue(), "the gauge is set once the isolation is refused")
		Expect(readyValue(name)()).To(BeZero())

		// A policy in the gateway group's namespace wakes the controller. Same reason, so no new count.
		r := reconciles("networkisolation")
		createUserPolicy(nsA, "wake", labelSel(appLabel, "other"), "Ingress")
		waitReconcile("networkisolation", r)
		r = reconciles("networkisolation")
		createUserPolicy(nsA, "wake-2", labelSel(appLabel, "other"), "Ingress")
		waitReconcile("networkisolation", r)
		Expect(counter(isolationRefusals, "PodCIDRUnknown")).To(Equal(before + 1))

		// Pod ranges return: Ready, gauge 1. Then delete: the series goes away.
		createNode("node-m", "10.42.7.0/24")
		Eventually(readyValue(name)).Should(Equal(1.0))
		Expect(k8sClient.Delete(ctx, iso)).To(Succeed())
		Eventually(func() bool { return hasReadySeries(name) }).Should(BeFalse(), "series for %s", name)
	})
})
