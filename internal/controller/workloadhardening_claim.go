package controller

import (
	"context"
	"fmt"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netsecv1alpha1 "github.com/nrndev/netsec/api/v1alpha1"
	"github.com/nrndev/netsec/internal/hardening"
)

// claimAnnotation names the claimed workload on its Lease, for people. A label cannot
// hold "kind/namespace/name".
const claimAnnotation = "netsec.nrnx.dev/workload"

// A run claims a workload with a Lease before it patches it. Creating an object is
// atomic, so when two runs race, one create fails: that is the guarantee. The plan-time
// ActiveSet skip stays as the friendly early path.

func (r *WorkloadHardeningReconciler) leaseKey(w netsecv1alpha1.PlannedWorkload) types.NamespacedName {
	return types.NamespacedName{Namespace: r.Namespace, Name: hardening.ClaimName(w.Kind, w.Namespace, w.Name)}
}

// claim takes the workload's Lease for this run. It returns "" when this run holds it,
// or the name of the run that does. A Lease whose holder is gone, or is not rolling this
// workload any more, is taken over; the resourceVersion makes that update optimistic.
func (p *pass) claim(ctx context.Context, w netsecv1alpha1.PlannedWorkload) (string, error) {
	uid := string(p.wh.UID)
	key := p.r.leaseKey(w)
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: key.Namespace, Name: key.Name,
			Annotations: map[string]string{claimAnnotation: hardening.WorkloadKey(w.Kind, w.Namespace, w.Name)},
		},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: &uid},
	}
	err := p.r.Create(ctx, lease)
	if err == nil {
		return "", nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return "", fmt.Errorf("claim %s %s/%s: %w", w.Kind, w.Namespace, w.Name, err)
	}
	cur := &coordinationv1.Lease{}
	if err := p.r.APIReader.Get(ctx, key, cur); err != nil {
		return "", fmt.Errorf("read claim of %s %s/%s: %w", w.Kind, w.Namespace, w.Name, err)
	}
	holder := ""
	if cur.Spec.HolderIdentity != nil {
		holder = *cur.Spec.HolderIdentity
	}
	if holder == uid {
		return "", nil
	}
	name, live, err := p.holderRun(ctx, holder, w)
	if err != nil || live {
		return name, err
	}
	cur.Spec.HolderIdentity = &uid
	if err := p.r.Update(ctx, cur); err != nil {
		return "", fmt.Errorf("take over the stale claim of %s %s/%s: %w", w.Kind, w.Namespace, w.Name, err)
	}
	return "", nil
}

// holderRun finds the run with the given UID. live is true if it is still rolling the
// workload: Applying or Undoing, with the workload Pending or in flight. Pending counts
// because a run claims before it saves the workload as Applying. name is the run's name,
// or the UID when no such run exists.
func (p *pass) holderRun(ctx context.Context, uid string, w netsecv1alpha1.PlannedWorkload) (name string, live bool, err error) {
	runs := &netsecv1alpha1.WorkloadHardeningList{}
	if err := p.r.APIReader.List(ctx, runs); err != nil {
		return "", false, fmt.Errorf("list WorkloadHardenings: %w", err)
	}
	for _, run := range runs.Items {
		if string(run.UID) != uid {
			continue
		}
		if ph := run.Status.Phase; (ph != netsecv1alpha1.PhaseApplying && ph != netsecv1alpha1.PhaseUndoing) || run.Status.Plan == nil {
			return run.Name, false, nil
		}
		for _, rw := range run.Status.Plan.Workloads {
			if rw.Kind == w.Kind && rw.Namespace == w.Namespace && rw.Name == w.Name {
				switch rw.State {
				case netsecv1alpha1.StatePending, netsecv1alpha1.StateApplying, netsecv1alpha1.StateUndoing:
					return run.Name, true, nil
				}
			}
		}
		return run.Name, false, nil
	}
	return uid, false, nil
}

// release deletes the workload's Lease if this run holds it. A Lease that changed hands
// meanwhile is left alone.
func (p *pass) release(ctx context.Context, w netsecv1alpha1.PlannedWorkload) error {
	cur := &coordinationv1.Lease{}
	err := p.r.APIReader.Get(ctx, p.r.leaseKey(w), cur)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read claim of %s %s/%s: %w", w.Kind, w.Namespace, w.Name, err)
	}
	if cur.Spec.HolderIdentity == nil || *cur.Spec.HolderIdentity != string(p.wh.UID) {
		return nil
	}
	err = p.r.Delete(ctx, cur, client.Preconditions{UID: &cur.UID, ResourceVersion: &cur.ResourceVersion})
	if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
		return fmt.Errorf("release claim of %s %s/%s: %w", w.Kind, w.Namespace, w.Name, err)
	}
	return nil
}

// releaseAll releases the claim of every workload in the plan, whatever its state.
func (p *pass) releaseAll(ctx context.Context) error {
	for _, w := range p.workloads() {
		if err := p.release(ctx, w); err != nil {
			return err
		}
	}
	return nil
}

// releaseFinished releases the claims of workloads that reached a final state between
// old and cur, the plans before and after a status write.
func (p *pass) releaseFinished(ctx context.Context, old, cur []netsecv1alpha1.PlannedWorkload) error {
	was := make(map[string]netsecv1alpha1.WorkloadState, len(old))
	for _, w := range old {
		was[hardening.WorkloadKey(w.Kind, w.Namespace, w.Name)] = w.State
	}
	for _, w := range cur {
		prev, ok := was[hardening.WorkloadKey(w.Kind, w.Namespace, w.Name)]
		if !ok || prev == w.State {
			continue
		}
		switch w.State {
		case netsecv1alpha1.StatePending, netsecv1alpha1.StateApplying, netsecv1alpha1.StateUndoing:
			continue
		}
		if err := p.release(ctx, w); err != nil {
			return err
		}
	}
	return nil
}
