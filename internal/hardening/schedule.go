package hardening

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/nrndev/netsec/api/v1alpha1"
)

// WorkloadKey names a workload for set lookups.
func WorkloadKey(kind v1alpha1.WorkloadKind, namespace, name string) string {
	return fmt.Sprintf("%s/%s/%s", kind, namespace, name)
}

// ClaimName is the name of the Lease that locks a workload: a fixed-length name, because
// workload names can be long.
func ClaimName(kind v1alpha1.WorkloadKind, namespace, name string) string {
	sum := sha256.Sum256([]byte(WorkloadKey(kind, namespace, name)))
	return "netsec-claim-" + hex.EncodeToString(sum[:])[:16]
}

// NextToStart returns the indexes of the workloads to start now: the first ones, in plan
// order, whose state is in pending, limited to the free slots (max minus those in state
// inflight).
func NextToStart(ws []v1alpha1.PlannedWorkload, pending []v1alpha1.WorkloadState, inflight v1alpha1.WorkloadState, max int) []int {
	free := max
	for _, w := range ws {
		if w.State == inflight {
			free--
		}
	}
	var out []int
	for i, w := range ws {
		if len(out) >= free {
			break
		}
		if slices.Contains(pending, w.State) {
			out = append(out, i)
		}
	}
	return out
}

// ActiveSet maps the workload keys that another run is about to change or is changing
// to that run's name. A run counts while it is Applying or Undoing, and only for
// workloads in state Pending, Applying or Undoing. self is this run's UID.
func ActiveSet(runs []v1alpha1.WorkloadHardening, self types.UID) map[string]string {
	out := map[string]string{}
	for _, run := range runs {
		if run.UID == self || run.Status.Plan == nil {
			continue
		}
		if run.Status.Phase != v1alpha1.PhaseApplying && run.Status.Phase != v1alpha1.PhaseUndoing {
			continue
		}
		for _, w := range run.Status.Plan.Workloads {
			switch w.State {
			case v1alpha1.StatePending, v1alpha1.StateApplying, v1alpha1.StateUndoing:
				out[WorkloadKey(w.Kind, w.Namespace, w.Name)] = run.Name
			}
		}
	}
	return out
}

// Rejection says whether err is the API server refusing our request (a 4xx status, such
// as a validation or admission failure or a field conflict). It returns the message.
// Anything else (timeouts, 5xx, network) is not a verdict on the workload: retry it.
func Rejection(err error) (string, bool) {
	var st apierrors.APIStatus
	if !errors.As(err, &st) {
		return "", false
	}
	code := st.Status().Code
	if code < 400 || code >= 500 || code == 429 || code == 408 {
		return "", false
	}
	return st.Status().Message, true
}

// HasApplied says whether a run has patched anything. Once it has, the run is spent:
// planning again under the same field manager would drop the fields recorded for Undo.
// Failed counts only with appliedAt, because a plan also marks workloads Failed (WouldFail)
// when its dry run is refused, and nothing was patched then.
func HasApplied(ws []v1alpha1.PlannedWorkload) bool {
	for _, w := range ws {
		if w.AppliedAt != nil {
			return true
		}
		switch w.State {
		case v1alpha1.StateApplying, v1alpha1.StateHealthy, v1alpha1.StateUnverified,
			v1alpha1.StateReverted, v1alpha1.StateUndoing, v1alpha1.StateUndone:
			return true
		}
	}
	return false
}

// NeedsPlan says whether Plan mode should build a plan now: when there is none yet, or
// the spec changed since the last one. Apply re-plans on its own and checks the hash.
func NeedsPlan(havePlan bool, observedGeneration, generation int64) bool {
	return !havePlan || observedGeneration != generation
}

// RevertExpired says whether a revert that keeps failing should be given up on: now is
// past appliedAt plus twice the rollout timeout. A missing appliedAt never expires.
func RevertExpired(appliedAt *metav1.Time, now time.Time, rolloutTimeout time.Duration) bool {
	return appliedAt != nil && now.After(appliedAt.Add(2*rolloutTimeout))
}

// ApplyTime is when the API server last applied our fields, read from managedFields
// (the server's clock, not ours). ok is false if manager has no Apply entry.
func ApplyTime(fields []metav1.ManagedFieldsEntry, manager string) (t metav1.Time, ok bool) {
	for _, f := range fields {
		if f.Manager == manager && f.Operation == metav1.ManagedFieldsOperationApply && f.Time != nil {
			return *f.Time, true
		}
	}
	return metav1.Time{}, false
}
