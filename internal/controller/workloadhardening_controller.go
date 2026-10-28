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
	"errors"
	"fmt"
	"slices"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	netsecv1alpha1 "github.com/nrndev/netsec/api/v1alpha1"
	"github.com/nrndev/netsec/internal/hardening"
)

const (
	hardeningManagerPrefix = "netsec-hardening-"
	// activeRequeue is how often rollouts are checked; idleRequeue is the refresh otherwise.
	activeRequeue = 5 * time.Second
	idleRequeue   = time.Minute
	// fallbackRolloutTimeout is used if the CRD default did not fill spec.rolloutTimeout.
	fallbackRolloutTimeout = 5 * time.Minute

	// finishRolloutsFinalizer keeps a deleted run until its rollouts have passed the health gate.
	finishRolloutsFinalizer = "netsec.nrnx.dev/finish-rollouts"

	reasonNoIssues = "NoIssues"
	condPlanStale  = "PlanStale"
	condRefused    = "Refused"
	condWaiting    = "WaitingForRollouts"
)

// WorkloadHardeningReconciler reconciles a WorkloadHardening object
type WorkloadHardeningReconciler struct {
	client.Client
	// APIReader reads straight from the API server: the object itself, Pods, and the
	// workloads we are about to patch, so a stale cache never decides a patch.
	APIReader client.Reader
	Scheme    *runtime.Scheme
	Recorder  events.EventRecorder
	// ProtectedNamespaces are never touched. Names starting with "kube-" never are.
	ProtectedNamespaces []string
	// Namespace is the operator's own: workload claims (Leases) live here.
	Namespace string
	// Now is the clock. Nil means time.Now. Tests set it to jump past rolloutTimeout.
	Now func() time.Time
}

// +kubebuilder:rbac:groups=netsec.nrnx.dev,resources=workloadhardenings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netsec.nrnx.dev,resources=workloadhardenings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=netsec.nrnx.dev,resources=workloadhardenings/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=limitranges,verbs=list
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace=netsec-system,resources=leases,verbs=get;create;update;delete
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

func (r *WorkloadHardeningReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// pass is one reconcile of one WorkloadHardening. base is the status as last written, so
// save can send only the difference.
type pass struct {
	r       *WorkloadHardeningReconciler
	wh      *netsecv1alpha1.WorkloadHardening
	base    *netsecv1alpha1.WorkloadHardening
	manager string
	// readyMessage is the Ready message of the plan just published, for the PlanReady event.
	readyMessage string
}

// Reconcile follows design §4. Each pass writes status after every workload it touches,
// so a restart resumes from status.
func (r *WorkloadHardeningReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()
	wh := &netsecv1alpha1.WorkloadHardening{}
	// Read the live object: a stale cached phase could re-plan over a run in progress.
	if err := r.APIReader.Get(ctx, req.NamespacedName, wh); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	uid := string(wh.UID)
	p := &pass{r: r, wh: wh, base: wh.DeepCopy(), manager: hardeningManagerPrefix + uid[:min(8, len(uid))]}
	if !wh.DeletionTimestamp.IsZero() {
		done, err := p.finalize(ctx)
		if err != nil || done {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: activeRequeue}, nil
	}
	if err := p.run(ctx); err != nil {
		return ctrl.Result{}, err
	}
	logf.FromContext(ctx).V(1).Info("reconciled", "action", wh.Spec.Action, "phase", wh.Status.Phase)
	return ctrl.Result{RequeueAfter: p.requeue()}, nil
}

func (p *pass) requeue() time.Duration {
	if ph := p.wh.Status.Phase; ph == netsecv1alpha1.PhaseApplying || ph == netsecv1alpha1.PhaseUndoing {
		return activeRequeue
	}
	return idleRequeue
}

func (p *pass) run(ctx context.Context) error {
	wh := p.wh
	switch {
	case wh.Spec.Action == netsecv1alpha1.ActionUndo:
		return p.undo(ctx)
	case wh.Spec.Action == netsecv1alpha1.ActionApply && wh.Status.Phase == netsecv1alpha1.PhaseApplying:
		return p.applyLoop(ctx)
	}
	// Plan, or Apply that has not started: finish what is in flight and start nothing new.
	if p.inFlight() {
		if err := p.settle(ctx, true); err != nil {
			return err
		}
		if p.inFlight() {
			return nil
		}
	}
	if wh.Spec.Action == netsecv1alpha1.ActionPlan {
		if hardening.HasApplied(p.workloads()) {
			return p.refuseSpent(ctx)
		}
		return p.plan(ctx)
	}
	return p.startApply(ctx)
}

// finalize runs when the run is deleted. It starts nothing and undoes nothing, but keeps
// gating the workloads in flight (and reverting those that fail) until none is left,
// then removes the finalizer. It reports whether the run may go.
func (p *pass) finalize(ctx context.Context) (bool, error) {
	if !controllerutil.ContainsFinalizer(p.wh, finishRolloutsFinalizer) {
		return true, nil
	}
	if err := p.settle(ctx, true); err != nil {
		return false, err
	}
	if p.inFlight() {
		if meta.FindStatusCondition(p.base.Status.Conditions, condWaiting) == nil {
			msg := "deleted while rollouts are in flight: waiting for their health gate"
			p.event(corev1.EventTypeNormal, condWaiting, "%s", msg)
			p.cond(metav1.Condition{Type: condWaiting, Status: metav1.ConditionTrue, Reason: "RolloutsInFlight", Message: msg})
		}
		return false, p.save(ctx)
	}
	if err := p.releaseAll(ctx); err != nil {
		return false, err
	}
	return true, p.setFinalizer(ctx, false)
}

// setFinalizer adds or removes the finish-rollouts finalizer with a patch that fails if
// the object changed, so a finalizer someone else added at the same time is not dropped.
func (p *pass) setFinalizer(ctx context.Context, add bool) error {
	cp := p.wh.DeepCopy()
	changed := controllerutil.RemoveFinalizer(cp, finishRolloutsFinalizer)
	if add {
		changed = controllerutil.AddFinalizer(cp, finishRolloutsFinalizer)
	}
	if !changed {
		return nil
	}
	if err := p.r.Patch(ctx, cp, client.MergeFromWithOptions(p.wh, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("update finalizers of %s: %w", p.wh.Name, err)
	}
	// Only metadata changes here: keep the status the pass is still building.
	p.wh.Finalizers, p.wh.ResourceVersion = cp.Finalizers, cp.ResourceVersion
	p.base.Finalizers, p.base.ResourceVersion = cp.Finalizers, cp.ResourceVersion
	return nil
}

func (p *pass) workloads() []netsecv1alpha1.PlannedWorkload {
	if p.wh.Status.Plan == nil {
		return nil
	}
	return p.wh.Status.Plan.Workloads
}

func (p *pass) workloadsOf(wh *netsecv1alpha1.WorkloadHardening) []netsecv1alpha1.PlannedWorkload {
	if wh.Status.Plan == nil {
		return nil
	}
	return wh.Status.Plan.Workloads
}

// find returns the plan entry for the same workload as k.
func (p *pass) find(k netsecv1alpha1.PlannedWorkload) *netsecv1alpha1.PlannedWorkload {
	for i := range p.workloads() {
		if w := &p.wh.Status.Plan.Workloads[i]; w.Kind == k.Kind && w.Namespace == k.Namespace && w.Name == k.Name {
			return w
		}
	}
	return &k
}

func (p *pass) inFlight() bool {
	for _, w := range p.workloads() {
		if w.State == netsecv1alpha1.StateApplying || w.State == netsecv1alpha1.StateUndoing {
			return true
		}
	}
	return false
}

func (p *pass) rolloutTimeout() time.Duration {
	if t := p.wh.Spec.RolloutTimeout.Duration; t > 0 {
		return t
	}
	return fallbackRolloutTimeout
}

func (p *pass) maxRollouts() int {
	return max(1, int(p.wh.Spec.MaxConcurrentRollouts))
}

func (p *pass) cond(c metav1.Condition) {
	c.ObservedGeneration = p.wh.Generation
	meta.SetStatusCondition(&p.wh.Status.Conditions, c)
}

// save writes status with a merge patch, only when something changed. After it returns,
// re-read pointers into the plan: the response replaces them.
func (p *pass) save(ctx context.Context) error {
	return p.write(ctx, true)
}

// write is save. With count set, it also counts workloads that reached a final state
// since the last write. A fresh plan is written with count unset: its states describe
// the cluster, they are not results of a run.
func (p *pass) write(ctx context.Context, count bool) error {
	p.wh.Status.ObservedGeneration = p.wh.Generation
	p.wh.Status.Summary = hardening.Summary(p.wh.Status.Phase, p.workloads())
	if equality.Semantic.DeepEqual(p.base.Status, p.wh.Status) {
		return nil
	}
	old := p.workloadsOf(p.base)
	if err := p.r.Status().Patch(ctx, p.wh, client.MergeFrom(p.base)); err != nil {
		return fmt.Errorf("update status of %s: %w", p.wh.Name, err)
	}
	if count {
		countWorkloadResults(old, p.workloads())
	}
	p.base = p.wh.DeepCopy()
	if !count {
		return nil
	}
	return p.releaseFinished(ctx, old, p.workloads())
}

func (p *pass) clearDegraded() {
	p.cond(metav1.Condition{Type: condDegraded, Status: metav1.ConditionFalse, Reason: reasonNoIssues, Message: "no issues found"})
}

func (p *pass) event(typ, reason, format string, args ...any) {
	p.r.Recorder.Eventf(p.wh, nil, typ, reason, reason, format, args...)
}

// ---- Plan ----

// plan builds a fresh plan from the cache and shows it (action: Plan).
func (p *pass) plan(ctx context.Context) error {
	// Plan again only when the spec changed. Apply re-plans live and checks the hash anyway.
	if !hardening.NeedsPlan(p.wh.Status.Plan != nil, p.wh.Status.ObservedGeneration, p.wh.Generation) {
		return nil
	}
	bp, err := p.buildPlan(ctx, p.r.Client)
	return p.publish(ctx, bp, err, func(oldHash string) {
		p.wh.Status.Phase = netsecv1alpha1.PhasePlanned
		meta.RemoveStatusCondition(&p.wh.Status.Conditions, condPlanStale)
		if oldHash != p.wh.Status.Plan.Hash {
			p.event(corev1.EventTypeNormal, "PlanReady", "plan %s is ready: %s", p.wh.Status.Plan.Hash, p.readyMessage)
		}
	})
}

// publish stores a fresh plan, or the refusal if there is none, then calls then and saves.
func (p *pass) publish(ctx context.Context, bp *builtPlan, err error, then func(oldHash string)) error {
	switch {
	case errors.Is(err, hardening.ErrTooManyWorkloads):
		return p.refuse(ctx, "TooManyWorkloads", err.Error())
	case errors.Is(err, errInvalidSelector):
		return p.refuse(ctx, "InvalidSelector", err.Error())
	case err != nil:
		return err
	}
	oldHash := ""
	if p.wh.Status.Plan != nil {
		oldHash = p.wh.Status.Plan.Hash
	}
	p.wh.Status.Plan = &netsecv1alpha1.HardeningPlan{Hash: bp.hash, Workloads: bp.workloads}
	p.readyMessage = bp.message()
	p.cond(metav1.Condition{Type: condReady, Status: metav1.ConditionTrue, Reason: "PlanReady", Message: p.readyMessage})
	p.clearDegraded()
	meta.RemoveStatusCondition(&p.wh.Status.Conditions, condRefused)
	then(oldHash)
	return p.write(ctx, false)
}

// refuse shows that no plan can be made. The old plan is dropped: it no longer describes
// the cluster. A plan that was applied is kept, because Undo needs it.
func (p *pass) refuse(ctx context.Context, reason, msg string) error {
	if !hardening.HasApplied(p.workloads()) {
		p.wh.Status.Phase = netsecv1alpha1.PhaseFailed
		p.wh.Status.Plan = nil
	}
	p.cond(metav1.Condition{Type: condRefused, Status: metav1.ConditionTrue, Reason: reason, Message: msg})
	p.cond(metav1.Condition{Type: condReady, Status: metav1.ConditionFalse, Reason: reason, Message: msg})
	meta.RemoveStatusCondition(&p.wh.Status.Conditions, condPlanStale)
	if old := meta.FindStatusCondition(p.base.Status.Conditions, condRefused); old == nil || old.Message != msg {
		p.event(corev1.EventTypeWarning, "PlanRefused", "%s", msg)
	}
	return p.write(ctx, false)
}

// refuseSpent refuses to plan or apply again after the run applied something. One run
// applies each object once: a second apply under the same field manager would drop the
// fields recorded for Undo. The plan and the phase stay, so Undo still works.
func (p *pass) refuseSpent(ctx context.Context) error {
	const msg = "this run already applied; create a new WorkloadHardening to harden again"
	if old := meta.FindStatusCondition(p.base.Status.Conditions, condRefused); old == nil || old.Reason != "AlreadyApplied" {
		p.event(corev1.EventTypeWarning, "PlanRefused", "%s", msg)
	}
	p.cond(metav1.Condition{Type: condRefused, Status: metav1.ConditionTrue, Reason: "AlreadyApplied", Message: msg})
	return p.write(ctx, false)
}

// ---- Apply ----

// startApply compares a fresh plan with the approved hash (action: Apply, phase not Applying).
func (p *pass) startApply(ctx context.Context) error {
	wh := p.wh
	// Apply finished: the run is over.
	if wh.Status.Phase == netsecv1alpha1.PhaseCompleted || (wh.Status.Phase == netsecv1alpha1.PhaseFailed && wh.Status.Plan != nil) {
		return nil
	}
	// Read the workloads live: the approval must be checked against what is there now.
	bp, err := p.buildPlan(ctx, p.r.APIReader)
	started := false
	err = p.publish(ctx, bp, err, func(oldHash string) {
		if bp.hash != wh.Spec.ApprovedPlanHash {
			wh.Status.Phase = netsecv1alpha1.PhasePlanned
			msg := fmt.Sprintf("approvedPlanHash %q does not match the current plan %s: review it and approve the new hash", wh.Spec.ApprovedPlanHash, bp.hash)
			old := meta.FindStatusCondition(p.base.Status.Conditions, condPlanStale)
			if old == nil || old.Status != metav1.ConditionTrue || oldHash != bp.hash {
				p.event(corev1.EventTypeWarning, "PlanStale", "%s", msg)
			}
			p.cond(metav1.Condition{Type: condPlanStale, Status: metav1.ConditionTrue, Reason: "ApprovedPlanMismatch", Message: msg})
			return
		}
		wh.Status.Phase = netsecv1alpha1.PhaseApplying
		p.cond(metav1.Condition{Type: condPlanStale, Status: metav1.ConditionFalse, Reason: "Approved", Message: "approvedPlanHash matches the plan"})
		started = true
	})
	if err != nil || !started {
		return err
	}
	return p.applyLoop(ctx)
}

// applyLoop is one pass while Applying: check what is rolling out, start more, then finish.
func (p *pass) applyLoop(ctx context.Context) error {
	if err := p.setFinalizer(ctx, true); err != nil {
		return err
	}
	if err := p.settle(ctx, true); err != nil {
		return err
	}
	pending := []netsecv1alpha1.WorkloadState{netsecv1alpha1.StatePending}
	for _, i := range hardening.NextToStart(p.workloads(), pending, netsecv1alpha1.StateApplying, p.maxRollouts()) {
		if err := p.start(ctx, &p.wh.Status.Plan.Workloads[i]); err != nil {
			return err
		}
		if err := p.save(ctx); err != nil {
			return err
		}
	}
	failed := p.failedNames()
	if len(failed) > 0 {
		p.cond(metav1.Condition{Type: condDegraded, Status: metav1.ConditionTrue, Reason: "WorkloadsFailed", Message: "failed: " + nameList(failed)})
	} else {
		p.clearDegraded()
	}
	if !p.hasState(netsecv1alpha1.StatePending, netsecv1alpha1.StateApplying) {
		p.wh.Status.Phase = netsecv1alpha1.PhaseCompleted
		if len(failed) > 0 {
			p.wh.Status.Phase = netsecv1alpha1.PhaseFailed
		}
	}
	return p.save(ctx)
}

func (p *pass) hasState(states ...netsecv1alpha1.WorkloadState) bool {
	for _, w := range p.workloads() {
		if slices.Contains(states, w.State) {
			return true
		}
	}
	return false
}

func (p *pass) failedNames() []string {
	var out []string
	for _, w := range p.workloads() {
		if w.State == netsecv1alpha1.StateFailed {
			out = append(out, fmt.Sprintf("%s %s/%s", w.Kind, w.Namespace, w.Name))
		}
	}
	return out
}

// start patches one Pending workload for real, if it is still as it was approved.
func (p *pass) start(ctx context.Context, w *netsecv1alpha1.PlannedWorkload) error {
	obj, err := p.get(ctx, *w)
	if apierrors.IsNotFound(err) {
		w.State, w.Reason = netsecv1alpha1.StateSkipped, "deleted during apply"
		return nil
	}
	if err != nil {
		return err
	}
	// A crash between our patch and the status write leaves the workload patched but still
	// Pending. Our field manager's Apply entry proves it was us: carry on from there.
	if at, ok := hardening.ApplyTime(obj.GetManagedFields(), p.manager); ok {
		w.AppliedAt, w.Generation, w.Reason = &at, obj.GetGeneration(), ""
		w.State = netsecv1alpha1.StateApplying
		p.markApplied(w)
		return nil
	}
	if obj.GetGeneration() != w.Generation {
		w.State, w.Reason = netsecv1alpha1.StateSkipped, "changed after the plan was approved"
		return nil
	}
	// The approval covers the workload as it was planned. Check the skip rules again on
	// what is there now: an opt-out label added since must still be honoured.
	nsLabels, err := namespaceLabels(ctx, p.r.APIReader, w.Namespace)
	if err != nil {
		return err
	}
	if nsLabels == nil {
		w.State, w.Reason = netsecv1alpha1.StateSkipped, "namespace deleted during apply"
		return nil
	}
	live := hardening.Candidate{
		Kind: string(w.Kind), Namespace: w.Namespace, Name: w.Name, Labels: obj.GetLabels(),
		Annotations: obj.GetAnnotations(), OwnerReferences: obj.GetOwnerReferences(), NamespaceLabels: nsLabels,
	}
	if reason := hardening.SkipReason(live, p.r.ProtectedNamespaces); reason != "" {
		w.State, w.Reason = netsecv1alpha1.StateSkipped, "no longer eligible: "+reason
		return nil
	}
	limitRanges, err := listLimitRanges(ctx, p.r.APIReader, w.Namespace)
	if err != nil {
		return err
	}
	tp := hardening.PlanTemplate(templateOf(obj), p.wh.Spec.StrictSecurity, p.wh.Spec.DefaultResources, limitRanges)
	if len(tp.Changes) == 0 {
		w.State = netsecv1alpha1.StateNoChange
		return nil
	}
	// The spec may have been edited after approval. Only what was approved is applied.
	if !slices.Equal(tp.Changes, w.Changes) {
		w.State, w.Reason = netsecv1alpha1.StateSkipped, "planned changes differ from the approval (spec or LimitRange changed)"
		return nil
	}
	ac, err := hardening.ApplyConfig(w.Kind, w.Namespace, w.Name, tp)
	if err != nil {
		return err
	}
	holder, err := p.claim(ctx, *w)
	if err != nil {
		return err
	}
	if holder != "" {
		w.State, w.Reason = netsecv1alpha1.StateSkipped, "claimed by run "+holder
		return nil
	}
	patched, err := p.ssa(ctx, *w, ac, false)
	if err != nil {
		if msg, rejected := hardening.Rejection(err); rejected {
			w.State, w.Reason = netsecv1alpha1.StateFailed, msg
			return nil
		}
		return err
	}
	// The API server's clock, so a skewed operator clock cannot move the health gate's window.
	at, ok := hardening.ApplyTime(patched.GetManagedFields(), p.manager)
	if !ok {
		at = metav1.NewTime(p.r.now())
	}
	w.AppliedAt, w.Generation, w.Reason = &at, patched.GetGeneration(), ""
	w.State = netsecv1alpha1.StateApplying
	p.event(corev1.EventTypeNormal, "WorkloadPatched", "patched %s %s/%s", w.Kind, w.Namespace, w.Name)
	p.markApplied(w)
	return nil
}

// markApplied is what follows a patch: a CronJob has no rollout to watch.
func (p *pass) markApplied(w *netsecv1alpha1.PlannedWorkload) {
	if w.Kind == netsecv1alpha1.KindCronJob {
		// The change reaches the next run; there is no rollout to watch.
		w.State, w.Reason = netsecv1alpha1.StateUnverified, "the change applies to the next run"
	}
}

// settle checks the workloads that are rolling out and saves after each one.
// Applying workloads are checked only if applying is true.
func (p *pass) settle(ctx context.Context, applying bool) error {
	for i := range p.workloads() {
		w := &p.wh.Status.Plan.Workloads[i]
		var err error
		switch w.State {
		case netsecv1alpha1.StateApplying:
			if applying {
				err = p.checkApplied(ctx, w)
			}
		case netsecv1alpha1.StateUndoing:
			err = p.checkUndone(ctx, w)
		}
		if err != nil {
			return err
		}
		if err := p.save(ctx); err != nil {
			return err
		}
	}
	return nil
}

// checkApplied runs the health gate on a workload we patched, and reverts it on failure.
func (p *pass) checkApplied(ctx context.Context, w *netsecv1alpha1.PlannedWorkload) error {
	obj, h, pods, err := p.gate(ctx, w)
	if apierrors.IsNotFound(err) {
		w.State, w.Reason = netsecv1alpha1.StateSkipped, "deleted during apply"
		return nil
	}
	if err != nil {
		return err
	}
	switch h.State {
	case hardening.Healthy, hardening.Unverified:
		w.State, w.Reason = netsecv1alpha1.WorkloadState(h.State), h.Reason
		p.event(corev1.EventTypeNormal, "WorkloadHealthy", "%s %s/%s is %s", w.Kind, w.Namespace, w.Name, h.State)
	case hardening.Failed:
		return p.revert(ctx, w, obj, pods, h.Reason)
	}
	return nil
}

// revert removes our fields from a workload that failed its health gate (design §4.4 step 5).
func (p *pass) revert(ctx context.Context, w *netsecv1alpha1.PlannedWorkload, obj client.Object, pods []corev1.Pod, reason string) error {
	// A StatefulSet's bad revision is saved before the revert: afterwards updateRevision
	// may be the good one, and a retry could not find the stuck pods any more.
	var stuck []corev1.Pod
	if sts, ok := obj.(*appsv1.StatefulSet); ok {
		if w.FailedRevision == "" && sts.Status.UpdateRevision != sts.Status.CurrentRevision {
			w.FailedRevision = sts.Status.UpdateRevision
			key := *w
			if err := p.save(ctx); err != nil {
				return err
			}
			w = p.find(key) // save replaced the plan
		}
		stuck = hardening.StuckPods(pods, w.FailedRevision)
	}
	err := p.applyEmpty(ctx, w)
	for i := 0; err == nil && i < len(stuck); i++ {
		if derr := p.r.Delete(ctx, &stuck[i]); client.IgnoreNotFound(derr) != nil {
			err = fmt.Errorf("delete stuck pod %s/%s: %w", stuck[i].Namespace, stuck[i].Name, derr)
		}
	}
	if err != nil {
		msg := fmt.Sprintf("could not revert %s %s/%s: %v", w.Kind, w.Namespace, w.Name, err)
		p.event(corev1.EventTypeWarning, "RevertFailed", "%s", msg)
		if hardening.RevertExpired(w.AppliedAt, p.r.now(), p.rolloutTimeout()) {
			// Retrying has not worked for twice the rollout timeout. Stop, so the run can
			// finish and its claim is released; someone has to fix the workload by hand.
			w.State, w.Reason = netsecv1alpha1.StateFailed, fmt.Sprintf("revert failed: %v; fix it by hand", err)
			p.cond(metav1.Condition{Type: condDegraded, Status: metav1.ConditionTrue, Reason: "RevertFailed", Message: msg})
			return nil
		}
		p.cond(metav1.Condition{Type: condDegraded, Status: metav1.ConditionTrue, Reason: "RevertFailed", Message: msg})
		if serr := p.save(ctx); serr != nil {
			return errors.Join(err, serr)
		}
		return err // the workload stays Applying, so the next pass checks and reverts again
	}
	w.State, w.Reason = netsecv1alpha1.StateReverted, reason
	p.event(corev1.EventTypeWarning, "WorkloadReverted", "reverted %s %s/%s: %s", w.Kind, w.Namespace, w.Name, reason)
	return nil
}

// ---- Undo ----

// undo removes our fields, up to maxConcurrentRollouts workloads at a time (action: Undo).
func (p *pass) undo(ctx context.Context) error {
	wh := p.wh
	if wh.Status.Phase == netsecv1alpha1.PhaseUndone {
		return nil
	}
	if wh.Status.Plan == nil {
		wh.Status.Phase = netsecv1alpha1.PhaseUndone
		return p.save(ctx)
	}
	for i := range wh.Status.Plan.Workloads {
		// A reverted workload already lost our fields.
		if w := &wh.Status.Plan.Workloads[i]; w.State == netsecv1alpha1.StateReverted {
			w.State, w.Reason = netsecv1alpha1.StateUndone, ""
		}
	}
	if err := p.setFinalizer(ctx, true); err != nil {
		return err
	}
	wh.Status.Phase = netsecv1alpha1.PhaseUndoing
	if err := p.save(ctx); err != nil {
		return err
	}
	// Workloads still Applying are undo targets, not something to wait for.
	if err := p.settle(ctx, false); err != nil {
		return err
	}
	targets := make([]netsecv1alpha1.WorkloadState, 0, 4)
	targets = append(targets, netsecv1alpha1.StateHealthy, netsecv1alpha1.StateUnverified, netsecv1alpha1.StateApplying)
	// A workload that waits on another run's claim keeps its state and is tried again on a
	// later pass. It must not hold a slot, so work on a copy of the states and mark it taken.
	ws := slices.Clone(p.workloads())
	for {
		started, blocked := 0, 0
		for _, i := range hardening.NextToStart(ws, targets, netsecv1alpha1.StateUndoing, p.maxRollouts()) {
			w := &p.wh.Status.Plan.Workloads[i]
			waiting, err := p.undoStart(ctx, w)
			if err != nil {
				return err
			}
			if err := p.save(ctx); err != nil {
				return err
			}
			w = &p.wh.Status.Plan.Workloads[i] // save replaced the plan
			if waiting {
				ws[i].State = ""
				blocked++
				continue
			}
			ws[i].State = w.State
			started++
		}
		if blocked == 0 || started+blocked == 0 {
			break
		}
	}
	if !p.hasState(append(targets, netsecv1alpha1.StateUndoing)...) {
		wh.Status.Phase = netsecv1alpha1.PhaseUndone
		p.event(corev1.EventTypeNormal, "UndoComplete", "removed the hardening fields set by %s", p.manager)
	}
	return p.save(ctx)
}

// undoStart removes our fields from one workload. It reports waiting when another run's
// claim blocks it: the workload keeps its state and the next pass tries again.
func (p *pass) undoStart(ctx context.Context, w *netsecv1alpha1.PlannedWorkload) (waiting bool, err error) {
	// Look first: applying an empty configuration to a missing workload would try to create it.
	if _, err := p.get(ctx, *w); apierrors.IsNotFound(err) {
		w.State, w.Reason = netsecv1alpha1.StateUndone, "deleted before the undo"
		return false, nil
	} else if err != nil {
		return false, err
	}
	holder, err := p.claim(ctx, *w)
	if err != nil {
		return false, err
	}
	if holder != "" {
		w.Reason = "waiting: claimed by run " + holder
		return true, nil
	}
	patched, err := p.applyEmptyObj(ctx, w)
	switch {
	case apierrors.IsNotFound(err):
		w.State, w.Reason = netsecv1alpha1.StateUndone, "deleted before the undo"
		return false, nil
	case err != nil:
		if msg, rejected := hardening.Rejection(err); rejected {
			w.State, w.Reason = netsecv1alpha1.StateFailed, "undo failed: "+msg
			return false, nil
		}
		return false, err
	}
	at := metav1.NewTime(p.r.now())
	w.State, w.Reason, w.AppliedAt, w.Generation = netsecv1alpha1.StateUndoing, "", &at, patched.GetGeneration()
	return false, nil
}

// checkUndone watches the rollout after an undo. A failure is reported as the reason,
// never reverted: the state we return to worked before.
func (p *pass) checkUndone(ctx context.Context, w *netsecv1alpha1.PlannedWorkload) error {
	_, h, _, err := p.gate(ctx, w)
	if apierrors.IsNotFound(err) {
		w.State, w.Reason = netsecv1alpha1.StateUndone, "deleted during the undo"
		return nil
	}
	if err != nil {
		return err
	}
	switch h.State {
	case hardening.Healthy, hardening.Unverified:
		w.State, w.Reason = netsecv1alpha1.StateUndone, ""
	case hardening.Failed:
		w.State, w.Reason = netsecv1alpha1.StateUndone, "rollout problem after the undo: "+h.Reason
	}
	return nil
}

// ---- Cluster access ----

// gate reads the workload and its pods live and runs the health gate.
func (p *pass) gate(ctx context.Context, w *netsecv1alpha1.PlannedWorkload) (client.Object, hardening.Health, []corev1.Pod, error) {
	obj, err := p.get(ctx, *w)
	if err != nil {
		return nil, hardening.Health{}, nil, err
	}
	var pods []corev1.Pod
	if sel := selectorOf(obj); sel != nil {
		s, err := metav1.LabelSelectorAsSelector(sel)
		if err != nil {
			return nil, hardening.Health{}, nil, fmt.Errorf("%s %s/%s has an invalid selector: %w", w.Kind, w.Namespace, w.Name, err)
		}
		list := &corev1.PodList{}
		if err := p.r.APIReader.List(ctx, list, client.InNamespace(w.Namespace), client.MatchingLabelsSelector{Selector: s}); err != nil {
			return nil, hardening.Health{}, nil, fmt.Errorf("list pods of %s %s/%s: %w", w.Kind, w.Namespace, w.Name, err)
		}
		pods = list.Items
	}
	appliedAt := p.r.now()
	if w.AppliedAt != nil {
		appliedAt = w.AppliedAt.Time
	}
	h, err := hardening.CheckHealth(obj, pods, appliedAt, p.r.now(), p.rolloutTimeout())
	if err != nil {
		return nil, h, nil, fmt.Errorf("check health of %s %s/%s: %w", w.Kind, w.Namespace, w.Name, err)
	}
	return obj, h, pods, nil
}

func newWorkload(kind netsecv1alpha1.WorkloadKind) (client.Object, error) {
	switch kind {
	case netsecv1alpha1.KindDeployment:
		return &appsv1.Deployment{}, nil
	case netsecv1alpha1.KindStatefulSet:
		return &appsv1.StatefulSet{}, nil
	case netsecv1alpha1.KindDaemonSet:
		return &appsv1.DaemonSet{}, nil
	case netsecv1alpha1.KindCronJob:
		return &batchv1.CronJob{}, nil
	}
	return nil, fmt.Errorf("unsupported workload kind %q", kind)
}

func templateOf(obj client.Object) *corev1.PodTemplateSpec {
	switch o := obj.(type) {
	case *appsv1.Deployment:
		return &o.Spec.Template
	case *appsv1.StatefulSet:
		return &o.Spec.Template
	case *appsv1.DaemonSet:
		return &o.Spec.Template
	case *batchv1.CronJob:
		return &o.Spec.JobTemplate.Spec.Template
	}
	return nil
}

// selectorOf returns the pod selector, or nil for a CronJob (it has no rollout to watch).
func selectorOf(obj client.Object) *metav1.LabelSelector {
	switch o := obj.(type) {
	case *appsv1.Deployment:
		return o.Spec.Selector
	case *appsv1.StatefulSet:
		return o.Spec.Selector
	case *appsv1.DaemonSet:
		return o.Spec.Selector
	}
	return nil
}

// get reads the workload straight from the API server.
func (p *pass) get(ctx context.Context, w netsecv1alpha1.PlannedWorkload) (client.Object, error) {
	obj, err := newWorkload(w.Kind)
	if err != nil {
		return nil, err
	}
	if err := p.r.APIReader.Get(ctx, types.NamespacedName{Namespace: w.Namespace, Name: w.Name}, obj); err != nil {
		return nil, fmt.Errorf("get %s %s/%s: %w", w.Kind, w.Namespace, w.Name, err)
	}
	return obj, nil
}

// ssa server-side applies ac with our field manager, without forcing, and returns the
// object the API server answered with. The error wraps the API error.
func (p *pass) ssa(ctx context.Context, w netsecv1alpha1.PlannedWorkload, ac runtime.ApplyConfiguration, dryRun bool) (client.Object, error) {
	obj, err := newWorkload(w.Kind)
	if err != nil {
		return nil, err
	}
	obj.SetName(w.Name)
	obj.SetNamespace(w.Namespace)
	data, err := json.Marshal(ac)
	if err != nil {
		return nil, fmt.Errorf("encode apply configuration for %s %s/%s: %w", w.Kind, w.Namespace, w.Name, err)
	}
	opts := []client.PatchOption{client.FieldOwner(p.manager)}
	if dryRun {
		opts = append(opts, client.DryRunAll)
	}
	if err := p.r.Patch(ctx, obj, client.RawPatch(types.ApplyPatchType, data), opts...); err != nil {
		verb := "apply"
		if dryRun {
			verb = "dry-run apply"
		}
		return nil, fmt.Errorf("%s to %s %s/%s: %w", verb, w.Kind, w.Namespace, w.Name, err)
	}
	return obj, nil
}

// applyEmptyObj applies identity only, which removes exactly the fields our manager set.
func (p *pass) applyEmptyObj(ctx context.Context, w *netsecv1alpha1.PlannedWorkload) (client.Object, error) {
	ac, err := hardening.EmptyApplyConfig(w.Kind, w.Namespace, w.Name)
	if err != nil {
		return nil, err
	}
	return p.ssa(ctx, *w, ac, false)
}

func (p *pass) applyEmpty(ctx context.Context, w *netsecv1alpha1.PlannedWorkload) error {
	_, err := p.applyEmptyObj(ctx, w)
	return err
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadHardeningReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netsecv1alpha1.WorkloadHardening{}).
		Named("workloadhardening").
		Complete(r)
}
