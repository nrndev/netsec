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
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	netsecv1alpha1 "github.com/nrndev/netsec/api/v1alpha1"
	"github.com/nrndev/netsec/internal/hardening"
)

const (
	webApp    = "web"
	testImage = "registry.k8s.io/pause:3.10"
	// claimNS stands in for the operator's namespace: workload claims (Leases) live there.
	claimNS = "default"
	// goodRev and badRev are StatefulSet revisions: the one before hardening and the one it made.
	goodRev = "db-1"
	// ignoreLabel with ignoreValue opts a workload or namespace out of hardening.
	ignoreLabel = "netsec.nrnx.dev/ignore"
	ignoreValue = "true"
	badRev      = "db-2"
)

// fakeClock lets a spec jump past rolloutTimeout.
type fakeClock struct {
	mu     sync.Mutex
	offset time.Duration
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset += d
}

var _ = Describe("WorkloadHardening controller", func() {
	var (
		n     int // makes every spec's names unique: envtest cannot finish deleting a namespace
		ns    string
		name  string
		clock *fakeClock
		stop  func()
	)

	BeforeEach(func() {
		SetDefaultEventuallyTimeout(45 * time.Second)
		SetDefaultEventuallyPollingInterval(100 * time.Millisecond)
		n++
		ns, name = fmt.Sprintf("h%d", n), fmt.Sprintf("wh-%d", n)
		clock = &fakeClock{}
		createNS(ns)
		stop = startHardeningManager(clock.Now)
	})

	AfterEach(func() {
		for _, nm := range []string{name, name + "-other"} {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &netsecv1alpha1.WorkloadHardening{ObjectMeta: metav1.ObjectMeta{Name: nm}}))).To(Succeed())
		}
		stop()
		// No manager is left to release the finalizer of a run that was still rolling out.
		for _, nm := range []string{name, name + "-other"} {
			wh := &netsecv1alpha1.WorkloadHardening{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: nm}, wh); err == nil && len(wh.Finalizers) > 0 {
				wh.Finalizers = nil
				Expect(k8sClient.Update(ctx, wh)).To(Succeed())
			}
		}
	})

	newWH := func(nm string, mut func(*netsecv1alpha1.WorkloadHardening)) *netsecv1alpha1.WorkloadHardening {
		wh := &netsecv1alpha1.WorkloadHardening{
			ObjectMeta: metav1.ObjectMeta{Name: nm},
			Spec:       netsecv1alpha1.WorkloadHardeningSpec{Namespaces: []string{ns}},
		}
		if mut != nil {
			mut(wh)
		}
		Expect(k8sClient.Create(ctx, wh)).To(Succeed())
		return wh
	}
	getWH := func(nm string) *netsecv1alpha1.WorkloadHardening {
		wh := &netsecv1alpha1.WorkloadHardening{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nm}, wh)).To(Succeed())
		return wh
	}
	waitWH := func(nm string, ok func(Gomega, *netsecv1alpha1.WorkloadHardening)) *netsecv1alpha1.WorkloadHardening {
		wh := &netsecv1alpha1.WorkloadHardening{}
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nm}, wh)).To(Succeed())
			ok(g, wh)
		}).Should(Succeed())
		return wh
	}
	waitPhase := func(nm string, phase netsecv1alpha1.HardeningPhase) *netsecv1alpha1.WorkloadHardening {
		return waitWH(nm, func(g Gomega, wh *netsecv1alpha1.WorkloadHardening) {
			g.Expect(wh.Status.Phase).To(Equal(phase))
			g.Expect(wh.Status.Summary).NotTo(BeEmpty())
			g.Expect(wh.Status.Plan).NotTo(BeNil())
		})
	}
	// waitState waits until the workload has the state, and returns the object.
	waitState := func(nm string, kind netsecv1alpha1.WorkloadKind, workload string, state netsecv1alpha1.WorkloadState) *netsecv1alpha1.WorkloadHardening {
		return waitWH(nm, func(g Gomega, wh *netsecv1alpha1.WorkloadHardening) {
			g.Expect(wh.Status.Plan).NotTo(BeNil())
			g.Expect(planned(wh, kind, workload).State).To(Equal(state))
		})
	}
	approve := func(nm, hash string, mut func(*netsecv1alpha1.WorkloadHardening)) {
		wh := getWH(nm)
		wh.Spec.Action, wh.Spec.ApprovedPlanHash = netsecv1alpha1.ActionApply, hash
		if mut != nil {
			mut(wh)
		}
		Expect(k8sClient.Update(ctx, wh)).To(Succeed())
	}
	cond := func(wh *netsecv1alpha1.WorkloadHardening, typ string) *metav1.Condition {
		return meta.FindStatusCondition(wh.Status.Conditions, typ)
	}
	getDeploy := func(workload string) *appsv1.Deployment {
		d := &appsv1.Deployment{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: workload}, d)).To(Succeed())
		return d
	}
	ours := func(wh *netsecv1alpha1.WorkloadHardening, fields []metav1.ManagedFieldsEntry) bool {
		for _, f := range fields {
			if f.Manager == "netsec-hardening-"+string(wh.UID)[:8] && f.Operation == metav1.ManagedFieldsOperationApply {
				return true
			}
		}
		return false
	}
	// fakeHealthy plays the Deployment controller: the rollout is done.
	fakeHealthy := func(g Gomega, workload string) {
		d := &appsv1.Deployment{}
		g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: workload}, d)).To(Succeed())
		d.Status = appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1, ReadyReplicas: 1}
		g.Expect(k8sClient.Status().Update(ctx, d)).To(Succeed())
	}
	// runApply plans, approves and returns the plan hash. The caller drives the rollout.
	runApply := func(mut func(*netsecv1alpha1.WorkloadHardening)) *netsecv1alpha1.WorkloadHardening {
		newWH(name, mut)
		wh := waitPhase(name, netsecv1alpha1.PhasePlanned)
		approve(name, wh.Status.Plan.Hash, mut)
		return wh
	}

	It("plans without touching anything, and reports why workloads are skipped", func() {
		web := createDeployment(ns, webApp, nil)
		createDeployment(ns, "priv", func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: new(true)}
		})
		createDeployment(ns, "argo", func(d *appsv1.Deployment) {
			d.Annotations = map[string]string{"argocd.argoproj.io/tracking-id": "x"}
		})
		createDeployment(ns, "optout", func(d *appsv1.Deployment) { d.Labels[ignoreLabel] = ignoreValue })
		createDeployment(ns, "owned", func(d *appsv1.Deployment) {
			d.OwnerReferences = []metav1.OwnerReference{{APIVersion: "example.dev/v1", Kind: "Foo", Name: "op", UID: "u1", Controller: new(true)}}
		})
		Expect(k8sClient.Create(ctx, &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "migrate"},
			Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{Name: "c", Image: testImage}}}}},
		})).To(Succeed())
		createPod(ns, "stray", map[string]string{appLabel: "stray"}, false)

		newWH(name, nil)
		wh := waitPhase(name, netsecv1alpha1.PhasePlanned)

		Expect(wh.Status.Plan.Hash).To(MatchRegexp(`^[0-9a-f]{16}$`))
		got := planned(wh, netsecv1alpha1.KindDeployment, webApp)
		Expect(got.State).To(Equal(netsecv1alpha1.StatePending))
		Expect(got.Generation).To(Equal(web.Generation))
		Expect(got.Changes).To(ContainElement("template.spec.securityContext.seccompProfile.type: <unset> → RuntimeDefault"))
		Expect(got.Changes).To(ContainElement("containers[app].resources.requests.memory: <unset> → 128Mi"))
		priv := planned(wh, netsecv1alpha1.KindDeployment, "priv")
		Expect(priv.State).To(Equal(netsecv1alpha1.StatePending))
		Expect(priv.Warnings).To(ContainElement(ContainSubstring("container is privileged")))
		Expect(planned(wh, netsecv1alpha1.KindDeployment, "argo")).To(HaveField("Reason", "managed by Argo CD"))
		Expect(planned(wh, netsecv1alpha1.KindDeployment, "optout").Reason).To(ContainSubstring("netsec.nrnx.dev/ignore=true"))
		Expect(planned(wh, netsecv1alpha1.KindDeployment, "owned").Reason).To(Equal("owned by Foo op"))
		for _, s := range []string{"argo", "optout", "owned"} {
			Expect(planned(wh, netsecv1alpha1.KindDeployment, s).State).To(Equal(netsecv1alpha1.StateSkipped))
		}
		ready := cond(wh, "Ready")
		Expect(ready.Reason).To(Equal("PlanReady"))
		Expect(ready.Message).To(ContainSubstring("Job " + ns + "/migrate"))
		Expect(ready.Message).To(ContainSubstring("Pod " + ns + "/stray"))

		Expect(getDeploy(webApp).Generation).To(Equal(web.Generation), "planning must not patch")
		Expect(ours(wh, getDeploy(webApp).ManagedFields)).To(BeFalse())
		waitEvent(name, "PlanReady", corev1.EventTypeNormal)
	})

	It("marks the plan stale and patches nothing when the approved hash is wrong", func() {
		web := createDeployment(ns, webApp, nil)
		newWH(name, nil)
		waitPhase(name, netsecv1alpha1.PhasePlanned)
		approve(name, "0123456789abcdef", nil)

		wh := waitWH(name, func(g Gomega, wh *netsecv1alpha1.WorkloadHardening) {
			g.Expect(cond(wh, "PlanStale")).NotTo(BeNil())
			g.Expect(cond(wh, "PlanStale").Status).To(Equal(metav1.ConditionTrue))
		})
		Expect(wh.Status.Phase).To(Equal(netsecv1alpha1.PhasePlanned))
		Expect(getDeploy(webApp).Generation).To(Equal(web.Generation))
		Expect(ours(wh, getDeploy(webApp).ManagedFields)).To(BeFalse())
		waitEvent(name, "PlanStale", corev1.EventTypeWarning)
	})

	It("marks the plan stale when a workload was edited after planning", func() {
		createDeployment(ns, webApp, nil)
		newWH(name, nil)
		planned1 := waitPhase(name, netsecv1alpha1.PhasePlanned)
		oldHash := planned1.Status.Plan.Hash

		d := getDeploy(webApp)
		d.Spec.Replicas = new(int32(2))
		Expect(k8sClient.Update(ctx, d)).To(Succeed())
		edited := getDeploy(webApp)
		approve(name, oldHash, nil)

		wh := waitWH(name, func(g Gomega, wh *netsecv1alpha1.WorkloadHardening) {
			g.Expect(cond(wh, "PlanStale")).NotTo(BeNil())
			g.Expect(cond(wh, "PlanStale").Status).To(Equal(metav1.ConditionTrue))
			g.Expect(wh.Status.Plan.Hash).NotTo(Equal(oldHash))
		})
		Expect(planned(wh, netsecv1alpha1.KindDeployment, webApp).Generation).To(Equal(edited.Generation))
		Expect(wh.Status.Phase).To(Equal(netsecv1alpha1.PhasePlanned))
		Expect(getDeploy(webApp).Generation).To(Equal(edited.Generation))
		Expect(ours(wh, getDeploy(webApp).ManagedFields)).To(BeFalse())
	})

	// maxMemoryLimitRange sets only max.memory; the API server fills in default.memory.
	maxMemoryLimitRange := func() {
		lr := &corev1.LimitRange{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "limits"},
			Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{
				Type: corev1.LimitTypeContainer,
				Max:  corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")},
			}}},
		}
		Expect(k8sClient.Create(ctx, lr)).To(Succeed())
		Expect(lr.Spec.Limits[0].Default).To(HaveKey(corev1.ResourceMemory), "the API server defaulted default from max")
	}

	It("leaves memory to a namespace LimitRange and still sets the CPU request", func() {
		createDeployment(ns, webApp, nil)
		maxMemoryLimitRange()
		newWH(name, nil)
		wh := waitPhase(name, netsecv1alpha1.PhasePlanned)

		got := planned(wh, netsecv1alpha1.KindDeployment, webApp)
		Expect(got.State).To(Equal(netsecv1alpha1.StatePending))
		Expect(got.Changes).To(ContainElement("containers[app].resources.requests.cpu: <unset> → 100m"))
		for _, c := range got.Changes {
			Expect(c).NotTo(ContainSubstring("memory"))
		}
		Expect(got.Warnings).To(ConsistOf(`memory defaults left to LimitRange "limits"`))
	})

	It("marks the plan stale when a LimitRange is added after planning", func() {
		web := createDeployment(ns, webApp, nil)
		newWH(name, nil)
		oldHash := waitPhase(name, netsecv1alpha1.PhasePlanned).Status.Plan.Hash
		maxMemoryLimitRange()
		approve(name, oldHash, nil)

		wh := waitWH(name, func(g Gomega, wh *netsecv1alpha1.WorkloadHardening) {
			g.Expect(cond(wh, "PlanStale")).NotTo(BeNil())
			g.Expect(cond(wh, "PlanStale").Status).To(Equal(metav1.ConditionTrue))
			g.Expect(wh.Status.Plan.Hash).NotTo(Equal(oldHash))
		})
		Expect(getDeploy(webApp).Generation).To(Equal(web.Generation))
		Expect(ours(wh, getDeploy(webApp).ManagedFields)).To(BeFalse())
	})

	It("skips the remaining workloads when a LimitRange is added during the run", func() {
		createDeployment(ns, "w1", nil)
		createDeployment(ns, "w2", nil)
		runApply(nil)
		waitState(name, netsecv1alpha1.KindDeployment, "w1", netsecv1alpha1.StateApplying)
		maxMemoryLimitRange()

		Eventually(func(g Gomega) {
			fakeHealthy(g, "w1")
			got := planned(getWH(name), netsecv1alpha1.KindDeployment, "w2")
			g.Expect(got.State).To(Equal(netsecv1alpha1.StateSkipped))
			g.Expect(got.Reason).To(Equal("planned changes differ from the approval (spec or LimitRange changed)"))
		}).Should(Succeed())
		Expect(ours(getWH(name), getDeploy("w2").ManagedFields)).To(BeFalse())
		Expect(getDeploy("w2").Spec.Template.Spec.Containers[0].Resources.Requests).To(BeEmpty())
	})

	It("applies the approved plan, sets only unset fields, and finishes when healthy", func() {
		healthy := counter(hardeningWorkloads, "Healthy")
		createDeployment(ns, webApp, func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].Resources = corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("64Mi")},
				Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
			}
		})
		runApply(nil)

		done := waitWH(name, func(g Gomega, wh *netsecv1alpha1.WorkloadHardening) {
			fakeHealthy(g, webApp)
			g.Expect(wh.Status.Phase).To(Equal(netsecv1alpha1.PhaseCompleted))
		})
		Expect(planned(done, netsecv1alpha1.KindDeployment, webApp).State).To(Equal(netsecv1alpha1.StateHealthy))
		Expect(cond(done, "PlanStale").Status).To(Equal(metav1.ConditionFalse))

		d := getDeploy(webApp)
		c := d.Spec.Template.Spec.Containers[0]
		Expect(d.Spec.Template.Spec.SecurityContext.SeccompProfile.Type).To(Equal(corev1.SeccompProfileTypeRuntimeDefault))
		Expect(*c.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(c.Resources.Requests.Memory().String()).To(Equal("64Mi"), "a value the user set stays")
		Expect(c.Resources.Limits.Memory().String()).To(Equal("256Mi"))
		Expect(c.Resources.Requests.Cpu().String()).To(Equal("100m"))
		Expect(ours(done, d.ManagedFields)).To(BeTrue())

		// The result is counted once, and a later reconcile of the finished run adds nothing.
		waitEvent(name, "WorkloadPatched", corev1.EventTypeNormal)
		waitEvent(name, "WorkloadHealthy", corev1.EventTypeNormal)
		Expect(counter(hardeningWorkloads, "Healthy")).To(Equal(healthy + 1))
		r := reconciles("workloadhardening")
		wh := getWH(name)
		wh.Annotations = map[string]string{"wake": "up"}
		Expect(k8sClient.Update(ctx, wh)).To(Succeed())
		waitReconcile("workloadhardening", r)
		Expect(counter(hardeningWorkloads, "Healthy")).To(Equal(healthy + 1))
	})

	It("rolls out one workload at a time when maxConcurrentRollouts is 1", func() {
		createDeployment(ns, "w1", nil)
		createDeployment(ns, "w2", nil)
		w2 := getDeploy("w2")
		runApply(nil)

		wh := waitState(name, netsecv1alpha1.KindDeployment, "w1", netsecv1alpha1.StateApplying)
		Expect(planned(wh, netsecv1alpha1.KindDeployment, "w2").State).To(Equal(netsecv1alpha1.StatePending))
		Expect(getDeploy("w2").Generation).To(Equal(w2.Generation), "w2 must wait for w1")

		Eventually(func(g Gomega) {
			fakeHealthy(g, "w1")
			wh := getWH(name)
			g.Expect(planned(wh, netsecv1alpha1.KindDeployment, "w1").State).To(Equal(netsecv1alpha1.StateHealthy))
			g.Expect(planned(wh, netsecv1alpha1.KindDeployment, "w2").State).To(Equal(netsecv1alpha1.StateApplying))
		}).Should(Succeed())
		Eventually(func(g Gomega) {
			fakeHealthy(g, "w2")
			g.Expect(getWH(name).Status.Phase).To(Equal(netsecv1alpha1.PhaseCompleted))
		}).Should(Succeed())
	})

	It("reverts a workload whose new pod fails", func() {
		reverted := counter(hardeningWorkloads, "Reverted")
		createDeployment(ns, webApp, nil)
		runApply(nil)
		waitState(name, netsecv1alpha1.KindDeployment, webApp, netsecv1alpha1.StateApplying)
		createFailingPod(ns, "web-bad", map[string]string{appLabel: webApp})

		waitState(name, netsecv1alpha1.KindDeployment, webApp, netsecv1alpha1.StateReverted)
		// The state and the phase are written one after the other, so wait for the phase too.
		wh := waitPhase(name, netsecv1alpha1.PhaseCompleted)
		Expect(planned(wh, netsecv1alpha1.KindDeployment, webApp).Reason).To(ContainSubstring("CreateContainerConfigError"))
		expectOriginalTemplate(getDeploy(webApp))
		Expect(ours(wh, getDeploy(webApp).ManagedFields)).To(BeFalse())
		Expect(counter(hardeningWorkloads, "Reverted")).To(Equal(reverted + 1))
		waitEvent(name, "WorkloadReverted", corev1.EventTypeWarning)
	})

	It("finishes the health gate of a run deleted mid-rollout, and reverts a failing workload first", func() {
		createDeployment(ns, webApp, nil)
		runApply(nil)
		waitState(name, netsecv1alpha1.KindDeployment, webApp, netsecv1alpha1.StateApplying)
		Expect(getWH(name).Finalizers).To(ContainElement(finishRolloutsFinalizer))

		Expect(k8sClient.Delete(ctx, &netsecv1alpha1.WorkloadHardening{ObjectMeta: metav1.ObjectMeta{Name: name}})).To(Succeed())
		wh := waitWH(name, func(g Gomega, wh *netsecv1alpha1.WorkloadHardening) {
			g.Expect(cond(wh, "WaitingForRollouts")).NotTo(BeNil())
		})
		Expect(wh.DeletionTimestamp.IsZero()).To(BeFalse(), "the run must wait, not vanish")
		Expect(planned(wh, netsecv1alpha1.KindDeployment, webApp).State).To(Equal(netsecv1alpha1.StateApplying))

		createFailingPod(ns, "web-bad", map[string]string{appLabel: webApp})
		Eventually(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Name: name}, &netsecv1alpha1.WorkloadHardening{})
		}).Should(MatchError(apierrors.IsNotFound, "the run to be gone"))
		expectOriginalTemplate(getDeploy(webApp))
	})

	It("deletes a run at once when nothing is in flight", func() {
		createDeployment(ns, webApp, nil)
		runApply(nil)
		Eventually(func(g Gomega) {
			fakeHealthy(g, webApp)
			g.Expect(getWH(name).Status.Phase).To(Equal(netsecv1alpha1.PhaseCompleted))
		}).Should(Succeed())

		Expect(k8sClient.Delete(ctx, &netsecv1alpha1.WorkloadHardening{ObjectMeta: metav1.ObjectMeta{Name: name}})).To(Succeed())
		Eventually(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Name: name}, &netsecv1alpha1.WorkloadHardening{})
		}).Should(MatchError(apierrors.IsNotFound, "the run to be gone"))
		Expect(getDeploy(webApp).Spec.Template.Spec.SecurityContext.SeccompProfile).NotTo(BeNil(), "deleting never undoes")
	})

	It("reverts a StatefulSet and deletes the stuck pod of the bad revision", func() {
		sts := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "db"},
			Spec: appsv1.StatefulSetSpec{
				ServiceName: "db", Replicas: new(int32(1)),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{appLabel: "db"}},
				Template: podTemplate(map[string]string{appLabel: "db"}),
			},
		}
		Expect(k8sClient.Create(ctx, sts)).To(Succeed())
		runApply(nil)
		waitState(name, netsecv1alpha1.KindStatefulSet, "db", netsecv1alpha1.StateApplying)

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(sts), sts)).To(Succeed())
		sts.Status = appsv1.StatefulSetStatus{ObservedGeneration: sts.Generation, Replicas: 1, CurrentRevision: goodRev, UpdateRevision: badRev}
		Expect(k8sClient.Status().Update(ctx, sts)).To(Succeed())
		createFailingPod(ns, "db-0", map[string]string{appLabel: "db", appsv1.ControllerRevisionHashLabelKey: badRev})

		waitState(name, netsecv1alpha1.KindStatefulSet, "db", netsecv1alpha1.StateReverted)
		Eventually(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "db-0"}, &corev1.Pod{})
		}).Should(MatchError(apierrors.IsNotFound, "pod db-0 to be deleted"))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(sts), sts)).To(Succeed())
		Expect(sts.Spec.Template.Spec.SecurityContext == nil || sts.Spec.Template.Spec.SecurityContext.SeccompProfile == nil).To(BeTrue())
	})

	// The revert succeeded earlier but deleting the pod failed: updateRevision already
	// equals currentRevision, so only the recorded failedRevision names the stuck pods.
	It("deletes the stuck pods of the recorded failedRevision on a retry", func() {
		sts := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "db"},
			Spec: appsv1.StatefulSetSpec{
				ServiceName: "db", Replicas: new(int32(1)),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{appLabel: "db"}},
				Template: podTemplate(map[string]string{appLabel: "db"}),
			},
		}
		Expect(k8sClient.Create(ctx, sts)).To(Succeed())
		runApply(nil)
		waitState(name, netsecv1alpha1.KindStatefulSet, "db", netsecv1alpha1.StateApplying)

		Eventually(func(g Gomega) {
			wh := getWH(name)
			for i := range wh.Status.Plan.Workloads {
				wh.Status.Plan.Workloads[i].FailedRevision = badRev
			}
			g.Expect(k8sClient.Status().Update(ctx, wh)).To(Succeed())
		}).Should(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(sts), sts)).To(Succeed())
		sts.Status = appsv1.StatefulSetStatus{ObservedGeneration: sts.Generation, Replicas: 1, CurrentRevision: goodRev, UpdateRevision: goodRev}
		Expect(k8sClient.Status().Update(ctx, sts)).To(Succeed())
		createFailingPod(ns, "db-0", map[string]string{appLabel: "db", appsv1.ControllerRevisionHashLabelKey: badRev})
		createFailingPod(ns, "db-keep", map[string]string{appLabel: "db", appsv1.ControllerRevisionHashLabelKey: goodRev})

		waitState(name, netsecv1alpha1.KindStatefulSet, "db", netsecv1alpha1.StateReverted)
		Eventually(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "db-0"}, &corev1.Pod{})
		}).Should(MatchError(apierrors.IsNotFound, "pod db-0 to be deleted"))
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "db-keep"}, &corev1.Pod{})).To(Succeed(), "a pod of another revision stays")
	})

	It("reverts a workload that does not become healthy within rolloutTimeout", func() {
		createDeployment(ns, webApp, nil)
		runApply(nil)
		waitState(name, netsecv1alpha1.KindDeployment, webApp, netsecv1alpha1.StateApplying)

		clock.Advance(31 * time.Minute)

		wh := waitState(name, netsecv1alpha1.KindDeployment, webApp, netsecv1alpha1.StateReverted)
		Expect(planned(wh, netsecv1alpha1.KindDeployment, webApp).Reason).To(ContainSubstring("did not finish within"))
		expectOriginalTemplate(getDeploy(webApp))
	})

	It("undoes only its own fields, and keeps a field another manager took over", func() {
		createDeployment(ns, webApp, nil)
		runApply(nil)
		Eventually(func(g Gomega) {
			fakeHealthy(g, webApp)
			g.Expect(getWH(name).Status.Phase).To(Equal(netsecv1alpha1.PhaseCompleted))
		}).Should(Succeed())

		// Someone else takes over the memory request we set.
		other, err := json.Marshal(map[string]any{
			"apiVersion": "apps/v1", "kind": "Deployment",
			"metadata": map[string]any{"name": webApp, "namespace": ns},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []map[string]any{
				{"name": appLabel, "resources": map[string]any{"requests": map[string]any{"memory": "256Mi"}}}}}}},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Patch(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: webApp, Namespace: ns}},
			client.RawPatch(types.ApplyPatchType, other), client.FieldOwner("someone-else"), client.ForceOwnership)).To(Succeed())

		wh := getWH(name)
		wh.Spec.Action = netsecv1alpha1.ActionUndo
		Expect(k8sClient.Update(ctx, wh)).To(Succeed())

		Eventually(func(g Gomega) {
			fakeHealthy(g, webApp)
			g.Expect(getWH(name).Status.Phase).To(Equal(netsecv1alpha1.PhaseUndone))
		}).Should(Succeed())
		done := getWH(name)
		Expect(planned(done, netsecv1alpha1.KindDeployment, webApp).State).To(Equal(netsecv1alpha1.StateUndone))

		d := getDeploy(webApp)
		c := d.Spec.Template.Spec.Containers[0]
		Expect(d.Spec.Template.Spec.SecurityContext == nil || d.Spec.Template.Spec.SecurityContext.SeccompProfile == nil).To(BeTrue(), "our pod field is gone")
		Expect(c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil).To(BeTrue(), "our container field is gone")
		Expect(c.Resources.Requests.Memory().String()).To(Equal("256Mi"), "the other manager's value stays")
		Expect(c.Resources.Requests.Cpu().IsZero()).To(BeTrue(), "our cpu request is gone")
		Expect(ours(done, d.ManagedFields)).To(BeFalse())
		waitEvent(name, "UndoComplete", corev1.EventTypeNormal)
	})

	It("refuses a plan with more than 200 targets", func() {
		for i := range 201 {
			createDeployment(ns, fmt.Sprintf("d%03d", i), nil)
		}
		newWH(name, nil)
		wh := waitWH(name, func(g Gomega, wh *netsecv1alpha1.WorkloadHardening) {
			g.Expect(cond(wh, "Refused")).NotTo(BeNil())
		})
		Expect(cond(wh, "Refused").Status).To(Equal(metav1.ConditionTrue))
		Expect(cond(wh, "Refused").Reason).To(Equal("TooManyWorkloads"))
		Expect(cond(wh, "Refused").Message).To(ContainSubstring("narrow namespaces or selector"))
		waitEvent(name, "PlanRefused", corev1.EventTypeWarning)
		Expect(wh.Status.Phase).To(Equal(netsecv1alpha1.PhaseFailed))
		Expect(wh.Status.Plan).To(BeNil())
	})

	It("skips workloads that another run is rolling out", func() {
		createDeployment(ns, "w1", nil)
		createDeployment(ns, "w2", nil)
		runApply(nil)
		waitState(name, netsecv1alpha1.KindDeployment, "w1", netsecv1alpha1.StateApplying) // w2 is Pending

		newWH(name+"-other", nil)
		wh := waitWH(name+"-other", func(g Gomega, wh *netsecv1alpha1.WorkloadHardening) {
			g.Expect(wh.Status.Plan).NotTo(BeNil())
		})
		for _, w := range []string{"w1", "w2"} {
			got := planned(wh, netsecv1alpha1.KindDeployment, w)
			Expect(got.State).To(Equal(netsecv1alpha1.StateSkipped))
			Expect(got.Reason).To(Equal("being changed by WorkloadHardening " + name))
		}
	})

	claimOf := func(workload string) types.NamespacedName {
		return types.NamespacedName{Namespace: claimNS, Name: hardening.ClaimName(netsecv1alpha1.KindDeployment, ns, workload)}
	}

	It("lets only one of two runs approved together patch a workload", func() {
		createDeployment(ns, webApp, nil)
		newWH(name, nil)
		newWH(name+"-other", nil)
		hashes := map[string]string{}
		for _, nm := range []string{name, name + "-other"} {
			hashes[nm] = waitPhase(nm, netsecv1alpha1.PhasePlanned).Status.Plan.Hash
		}
		for nm, h := range hashes {
			approve(nm, h, nil)
		}

		patchedBy := func() int {
			n := 0
			for _, nm := range []string{name, name + "-other"} {
				if ours(getWH(nm), getDeploy(webApp).ManagedFields) {
					n++
				}
			}
			return n
		}
		Eventually(patchedBy).Should(Equal(1))
		Consistently(patchedBy, 3*time.Second).Should(Equal(1))
	})

	It("refuses a workload whose claim is held by a run that is rolling it out", func() {
		createDeployment(ns, webApp, nil)
		runApply(nil)
		waitState(name, netsecv1alpha1.KindDeployment, webApp, netsecv1alpha1.StateApplying)
		holder := getWH(name)
		Expect(k8sClient.Get(ctx, claimOf(webApp), &coordinationv1.Lease{})).To(Succeed())

		other := newWH(name+"-other", nil)
		p := &pass{r: &WorkloadHardeningReconciler{Client: k8sClient, APIReader: k8sClient, Namespace: claimNS}, wh: other}
		got, err := p.claim(ctx, netsecv1alpha1.PlannedWorkload{Kind: netsecv1alpha1.KindDeployment, Namespace: ns, Name: webApp})
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(holder.Name))
	})

	It("takes over a stale claim, and releases it when the workload is done", func() {
		createDeployment(ns, webApp, nil)
		gone := "uid-of-a-deleted-run"
		Expect(k8sClient.Create(ctx, &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Namespace: claimNS, Name: claimOf(webApp).Name},
			Spec:       coordinationv1.LeaseSpec{HolderIdentity: &gone},
		})).To(Succeed())
		runApply(nil)

		Eventually(func(g Gomega) {
			lease := &coordinationv1.Lease{}
			g.Expect(k8sClient.Get(ctx, claimOf(webApp), lease)).To(Succeed())
			g.Expect(*lease.Spec.HolderIdentity).To(Equal(string(getWH(name).UID)))
		}).Should(Succeed())
		Eventually(func(g Gomega) {
			fakeHealthy(g, webApp)
			g.Expect(getWH(name).Status.Phase).To(Equal(netsecv1alpha1.PhaseCompleted))
		}).Should(Succeed())
		Eventually(func() error { return k8sClient.Get(ctx, claimOf(webApp), &coordinationv1.Lease{}) }).
			Should(MatchError(apierrors.IsNotFound, "the claim to be released"))
	})

	// edit changes the run's spec. The controller writes status too, so retry on a conflict.
	edit := func(nm string, mut func(*netsecv1alpha1.WorkloadHardening)) {
		GinkgoHelper()
		Eventually(func() error {
			wh := &netsecv1alpha1.WorkloadHardening{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: nm}, wh); err != nil {
				return err
			}
			mut(wh)
			return k8sClient.Update(ctx, wh)
		}).Should(Succeed())
	}
	completed := func(workloads ...string) {
		GinkgoHelper()
		Eventually(func(g Gomega) {
			for _, w := range workloads {
				fakeHealthy(g, w)
			}
			g.Expect(getWH(name).Status.Phase).To(Equal(netsecv1alpha1.PhaseCompleted))
		}).Should(Succeed())
	}

	It("refuses to plan again once the run has applied, and Undo still works", func() {
		createDeployment(ns, webApp, nil)
		runApply(nil)
		completed(webApp)
		before := getWH(name)
		template := getDeploy(webApp).Spec.Template

		edit(name, func(wh *netsecv1alpha1.WorkloadHardening) { wh.Spec.Action = netsecv1alpha1.ActionPlan })
		got := waitWH(name, func(g Gomega, wh *netsecv1alpha1.WorkloadHardening) {
			g.Expect(cond(wh, "Refused")).NotTo(BeNil())
			g.Expect(cond(wh, "Refused").Reason).To(Equal("AlreadyApplied"))
		})
		Expect(got.Status.Plan).To(Equal(before.Status.Plan))
		Expect(got.Status.Phase).To(Equal(netsecv1alpha1.PhaseCompleted))
		Expect(getDeploy(webApp).Spec.Template).To(Equal(template), "the workload is unchanged")
		Expect(ours(got, getDeploy(webApp).ManagedFields)).To(BeTrue(), "our fields are still recorded")
		// A longer look: no later pass may re-plan or drop what Undo needs.
		Consistently(func() *netsecv1alpha1.HardeningPlan { return getWH(name).Status.Plan }, 3*time.Second).Should(Equal(before.Status.Plan))

		edit(name, func(wh *netsecv1alpha1.WorkloadHardening) { wh.Spec.Action = netsecv1alpha1.ActionUndo })
		Eventually(func(g Gomega) {
			fakeHealthy(g, webApp)
			g.Expect(getWH(name).Status.Phase).To(Equal(netsecv1alpha1.PhaseUndone))
		}).Should(Succeed())
		expectOriginalTemplate(getDeploy(webApp))
		Expect(ours(getWH(name), getDeploy(webApp).ManagedFields)).To(BeFalse())
	})

	It("does not plan again while the spec is unchanged", func() {
		createDeployment(ns, "w1", nil)
		newWH(name, nil)
		first := waitPhase(name, netsecv1alpha1.PhasePlanned)
		createDeployment(ns, "w2", nil)
		r := reconciles("workloadhardening")
		// Only metadata changes, so the generation stays and nothing needs a new plan.
		wh := getWH(name)
		Expect(k8sClient.Patch(ctx, wh, client.RawPatch(types.MergePatchType, []byte(`{"metadata":{"annotations":{"wake":"up"}}}`)))).To(Succeed())
		Expect(wh.Generation).To(Equal(first.Generation))
		waitReconcile("workloadhardening", r)
		Expect(getWH(name).Status.Plan.Workloads).To(HaveLen(len(first.Status.Plan.Workloads)), "w2 is not planned until the spec changes")
		edit(name, func(wh *netsecv1alpha1.WorkloadHardening) { wh.Spec.StrictSecurity.RunAsNonRoot = true })
		waitWH(name, func(g Gomega, wh *netsecv1alpha1.WorkloadHardening) {
			g.Expect(wh.Status.Plan.Workloads).To(HaveLen(2))
		})
	})

	It("resumes a workload that was patched before a crash instead of skipping it", func() {
		createDeployment(ns, "w1", nil)
		createDeployment(ns, "w2", nil)
		runApply(nil)
		waitState(name, netsecv1alpha1.KindDeployment, "w1", netsecv1alpha1.StateApplying) // w2 is Pending

		// Play the crash: our patch of w2 went through, the status write did not.
		data := fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"w2","namespace":%q},`+
			`"spec":{"template":{"spec":{"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}}}}}}`, ns)
		manager := "netsec-hardening-" + string(getWH(name).UID)[:8]
		Expect(k8sClient.Patch(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "w2", Namespace: ns}},
			client.RawPatch(types.ApplyPatchType, []byte(data)), client.FieldOwner(manager), client.ForceOwnership)).To(Succeed())

		Eventually(func(g Gomega) {
			fakeHealthy(g, "w1")
			wh := getWH(name)
			g.Expect(planned(wh, netsecv1alpha1.KindDeployment, "w2").State).To(Equal(netsecv1alpha1.StateApplying))
		}).Should(Succeed())
		w2 := planned(getWH(name), netsecv1alpha1.KindDeployment, "w2")
		Expect(w2.AppliedAt).NotTo(BeNil())
		Expect(w2.Generation).To(Equal(getDeploy("w2").Generation))
		completed("w1", "w2")
	})

	It("skips a workload that got the opt-out label after approval", func() {
		createDeployment(ns, "w1", nil)
		createDeployment(ns, "w2", nil)
		runApply(nil)
		waitState(name, netsecv1alpha1.KindDeployment, "w1", netsecv1alpha1.StateApplying)

		d := getDeploy("w2")
		d.Labels[ignoreLabel] = ignoreValue
		Expect(k8sClient.Update(ctx, d)).To(Succeed())
		generation := getDeploy("w2").Generation

		Eventually(func(g Gomega) {
			fakeHealthy(g, "w1")
			wh := getWH(name)
			g.Expect(planned(wh, netsecv1alpha1.KindDeployment, "w2").State).To(Equal(netsecv1alpha1.StateSkipped))
		}).Should(Succeed())
		Expect(planned(getWH(name), netsecv1alpha1.KindDeployment, "w2").Reason).To(ContainSubstring("no longer eligible"))
		Expect(getDeploy("w2").Generation).To(Equal(generation), "w2 was not patched")
		Expect(ours(getWH(name), getDeploy("w2").ManagedFields)).To(BeFalse())
	})

	It("skips the remaining workloads when the spec was edited after approval", func() {
		createDeployment(ns, "w1", nil)
		createDeployment(ns, "w2", nil)
		createDeployment(ns, "w3", nil)
		runApply(nil)
		waitState(name, netsecv1alpha1.KindDeployment, "w1", netsecv1alpha1.StateApplying)

		edit(name, func(wh *netsecv1alpha1.WorkloadHardening) {
			wh.Spec.DefaultResources.Requests.CPU = resource.MustParse("500m")
		})
		Eventually(func(g Gomega) {
			fakeHealthy(g, "w1")
			wh := getWH(name)
			for _, w := range []string{"w2", "w3"} {
				got := planned(wh, netsecv1alpha1.KindDeployment, w)
				g.Expect(got.State).To(Equal(netsecv1alpha1.StateSkipped))
				g.Expect(got.Reason).To(Equal("planned changes differ from the approval (spec or LimitRange changed)"))
			}
		}).Should(Succeed())
		Expect(ours(getWH(name), getDeploy("w2").ManagedFields)).To(BeFalse())
		Expect(getDeploy("w3").Spec.Template.Spec.Containers[0].Resources.Requests).To(BeEmpty())
	})

	It("makes an Undo wait while another run holds the workload, then finishes it", func() {
		createDeployment(ns, webApp, nil)
		// Run one hardens the workload and finishes.
		other := name + "-other"
		newWH(other, nil)
		hash := waitPhase(other, netsecv1alpha1.PhasePlanned).Status.Plan.Hash
		approve(other, hash, nil)
		Eventually(func(g Gomega) {
			fakeHealthy(g, webApp)
			g.Expect(getWH(other).Status.Phase).To(Equal(netsecv1alpha1.PhaseCompleted))
		}).Should(Succeed())
		// Run two asks for more, so it has a change to make and holds the claim while it rolls out.
		runApply(func(wh *netsecv1alpha1.WorkloadHardening) { wh.Spec.StrictSecurity.RunAsNonRoot = true })
		waitState(name, netsecv1alpha1.KindDeployment, webApp, netsecv1alpha1.StateApplying)

		edit(other, func(wh *netsecv1alpha1.WorkloadHardening) { wh.Spec.Action = netsecv1alpha1.ActionUndo })
		waiting := waitWH(other, func(g Gomega, wh *netsecv1alpha1.WorkloadHardening) {
			w := planned(wh, netsecv1alpha1.KindDeployment, webApp)
			g.Expect(w.Reason).To(Equal("waiting: claimed by run " + name))
		})
		Expect(planned(waiting, netsecv1alpha1.KindDeployment, webApp).State).To(Equal(netsecv1alpha1.StateHealthy), "the state is kept")
		Expect(waiting.Status.Phase).To(Equal(netsecv1alpha1.PhaseUndoing))

		// Run two finishes and lets go of the claim: the Undo goes through.
		Eventually(func(g Gomega) {
			fakeHealthy(g, webApp)
			g.Expect(getWH(other).Status.Phase).To(Equal(netsecv1alpha1.PhaseUndone))
		}).Should(Succeed())
		Expect(planned(getWH(other), netsecv1alpha1.KindDeployment, webApp).State).To(Equal(netsecv1alpha1.StateUndone))
	})

	It("finishes an Undo of a workload that was deleted", func() {
		createDeployment(ns, webApp, nil)
		runApply(nil)
		completed(webApp)
		Expect(k8sClient.Delete(ctx, getDeploy(webApp))).To(Succeed())

		edit(name, func(wh *netsecv1alpha1.WorkloadHardening) { wh.Spec.Action = netsecv1alpha1.ActionUndo })
		done := waitPhase(name, netsecv1alpha1.PhaseUndone)
		w := planned(done, netsecv1alpha1.KindDeployment, webApp)
		Expect(w.State).To(Equal(netsecv1alpha1.StateUndone))
		Expect(w.Reason).To(Equal("deleted before the undo"))
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: webApp}, &appsv1.Deployment{})).To(MatchError(apierrors.IsNotFound, "the workload must not be created again"))
	})

	It("skips workloads in a protected namespace or one with the opt-out label, and never patches them", func() {
		optOut := ns + "-optout"
		createNS(optOut)
		nsObj := &corev1.Namespace{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: optOut}, nsObj)).To(Succeed())
		nsObj.Labels = map[string]string{ignoreLabel: ignoreValue}
		Expect(k8sClient.Update(ctx, nsObj)).To(Succeed())
		createNS(protectedNS)
		protectedWeb := fmt.Sprintf("prot-%d", n) // the namespace outlives the spec, so the name must be new
		createDeployment(protectedNS, protectedWeb, nil)
		createDeployment(optOut, webApp, nil)
		createDeployment(ns, webApp, nil)

		newWH(name, func(wh *netsecv1alpha1.WorkloadHardening) {
			wh.Spec.Namespaces = []string{ns, protectedNS, optOut}
		})
		wh := waitPhase(name, netsecv1alpha1.PhasePlanned)
		Expect(planned(wh, netsecv1alpha1.KindDeployment, webApp).State).To(Equal(netsecv1alpha1.StatePending), "the ordinary namespace is still planned")
		var protectedSkips, optOutSkips int
		for _, w := range wh.Status.Plan.Workloads {
			if w.State != netsecv1alpha1.StateSkipped {
				continue
			}
			switch w.Namespace {
			case protectedNS:
				Expect(w.Reason).To(ContainSubstring("protected"))
				protectedSkips++
			case optOut:
				Expect(w.Reason).To(ContainSubstring("labelled"))
				optOutSkips++
			}
		}
		Expect(optOutSkips).To(Equal(1))
		Expect(protectedSkips).To(Equal(1))

		approve(name, wh.Status.Plan.Hash, nil)
		completed(webApp)
		for _, key := range []types.NamespacedName{{Namespace: optOut, Name: webApp}, {Namespace: protectedNS, Name: protectedWeb}} {
			d := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, key, d)).To(Succeed())
			Expect(ours(getWH(name), d.ManagedFields)).To(BeFalse(), "%s must not be patched", key)
		}
	})

	It("starts as many rollouts at once as maxConcurrentRollouts allows", func() {
		createDeployment(ns, "w1", nil)
		createDeployment(ns, "w2", nil)
		createDeployment(ns, "w3", nil)
		runApply(func(wh *netsecv1alpha1.WorkloadHardening) { wh.Spec.MaxConcurrentRollouts = 2 })

		wh := waitWH(name, func(g Gomega, wh *netsecv1alpha1.WorkloadHardening) {
			g.Expect(wh.Status.Plan).NotTo(BeNil())
			g.Expect(planned(wh, netsecv1alpha1.KindDeployment, "w1").State).To(Equal(netsecv1alpha1.StateApplying))
			g.Expect(planned(wh, netsecv1alpha1.KindDeployment, "w2").State).To(Equal(netsecv1alpha1.StateApplying))
		})
		Expect(planned(wh, netsecv1alpha1.KindDeployment, "w3").State).To(Equal(netsecv1alpha1.StatePending), "the third waits for a free slot")
		completed("w1", "w2", "w3")
	})

	It("marks a CronJob Unverified right after the patch", func() {
		cj := &batchv1.CronJob{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nightly"},
			Spec: batchv1.CronJobSpec{Schedule: "0 3 * * *", JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{Name: appLabel, Image: testImage}}}}}}},
		}
		Expect(k8sClient.Create(ctx, cj)).To(Succeed())
		runApply(nil)

		wh := waitPhase(name, netsecv1alpha1.PhaseCompleted)
		Expect(planned(wh, netsecv1alpha1.KindCronJob, "nightly").State).To(Equal(netsecv1alpha1.StateUnverified))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cj), cj)).To(Succeed())
		Expect(cj.Spec.JobTemplate.Spec.Template.Spec.SecurityContext.SeccompProfile.Type).To(Equal(corev1.SeccompProfileTypeRuntimeDefault))
	})
})

func planned(wh *netsecv1alpha1.WorkloadHardening, kind netsecv1alpha1.WorkloadKind, name string) netsecv1alpha1.PlannedWorkload {
	GinkgoHelper()
	for _, w := range wh.Status.Plan.Workloads {
		if w.Kind == kind && w.Name == name {
			return w
		}
	}
	Fail(fmt.Sprintf("%s %s is not in the plan: %+v", kind, name, wh.Status.Plan.Workloads))
	return netsecv1alpha1.PlannedWorkload{}
}

func podTemplate(labels map[string]string) corev1.PodTemplateSpec {
	return corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: appLabel, Image: testImage}}},
	}
}

func createDeployment(ns, name string, mut func(*appsv1.Deployment)) *appsv1.Deployment {
	GinkgoHelper()
	labels := map[string]string{appLabel: name}
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{appLabel: name}},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: podTemplate(labels),
		},
	}
	if mut != nil {
		mut(d)
	}
	Expect(k8sClient.Create(ctx, d)).To(Succeed())
	return d
}

// createFailingPod makes a pod stuck in CreateContainerConfigError, like a bad securityContext would.
func createFailingPod(ns, name string, labels map[string]string) {
	GinkgoHelper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Spec:       podTemplate(labels).Spec,
	}
	Expect(k8sClient.Create(ctx, pod)).To(Succeed())
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  "app",
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CreateContainerConfigError"}},
	}}
	Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
}

// expectOriginalTemplate checks that none of the fields we set are left.
func expectOriginalTemplate(d *appsv1.Deployment) {
	GinkgoHelper()
	spec := d.Spec.Template.Spec
	Expect(spec.SecurityContext == nil || spec.SecurityContext.SeccompProfile == nil).To(BeTrue())
	c := spec.Containers[0]
	Expect(c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil).To(BeTrue())
	Expect(c.Resources.Requests).To(BeEmpty())
	Expect(c.Resources.Limits).To(BeEmpty())
}

// startHardeningManager runs the controller in its own manager with the given clock.
func startHardeningManager(now func() time.Time) func() {
	GinkgoHelper()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:     scheme.Scheme,
		Metrics:    metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{SkipNameValidation: new(true)},
	})
	Expect(err).NotTo(HaveOccurred())
	Expect((&WorkloadHardeningReconciler{
		Client:              mgr.GetClient(),
		APIReader:           mgr.GetAPIReader(),
		Scheme:              mgr.GetScheme(),
		Recorder:            mgr.GetEventRecorder("netsec-hardening-test"),
		ProtectedNamespaces: []string{protectedNS},
		Namespace:           claimNS,
		Now:                 now,
	}).SetupWithManager(mgr)).To(Succeed())

	mctx, cancelMgr := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer GinkgoRecover()
		defer close(done)
		Expect(mgr.Start(mctx)).To(Succeed())
	}()
	return func() {
		cancelMgr()
		<-done
	}
}
