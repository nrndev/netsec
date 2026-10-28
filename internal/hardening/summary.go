package hardening

import (
	"fmt"
	"strings"

	"github.com/nrndev/netsec/api/v1alpha1"
)

const failed = "failed"

// part is one "<count> <words>" piece of a summary: the words for every workload in state.
type part struct {
	state v1alpha1.WorkloadState
	words string
}

// Summary is the one-line count shown in status.summary and `kubectl get wh`.
// It counts workloads by state in plain words and leaves out zero counts.
func Summary(phase v1alpha1.HardeningPhase, ws []v1alpha1.PlannedWorkload) string {
	var parts []part
	switch phase {
	case v1alpha1.PhasePlanning, v1alpha1.PhasePlanned:
		if len(ws) == 0 {
			return "no workloads matched"
		}
		parts = []part{
			{v1alpha1.StatePending, "to change"},
			{v1alpha1.StateSkipped, "skipped"},
			{v1alpha1.StateNoChange, "already hardened"},
			{v1alpha1.StateFailed, "would fail"},
		}
	case v1alpha1.PhaseApplying:
		parts = []part{
			{v1alpha1.StateApplying, "rolling out"},
			{v1alpha1.StateHealthy, "healthy"},
			{v1alpha1.StateUnverified, "unverified"},
			{v1alpha1.StatePending, "waiting"},
			{v1alpha1.StateReverted, "reverted"},
			{v1alpha1.StateFailed, failed},
		}
	case v1alpha1.PhaseCompleted, v1alpha1.PhaseFailed:
		parts = []part{
			{v1alpha1.StateHealthy, "healthy"},
			{v1alpha1.StateUnverified, "unverified"},
			{v1alpha1.StateReverted, "reverted"},
			{v1alpha1.StateFailed, failed},
		}
	case v1alpha1.PhaseUndoing, v1alpha1.PhaseUndone:
		parts = []part{
			{v1alpha1.StateUndone, "undone"},
			{v1alpha1.StateUndoing, "undoing"},
			{v1alpha1.StateFailed, failed},
		}
	default:
		return ""
	}
	counts := map[v1alpha1.WorkloadState]int{}
	for _, w := range ws {
		counts[w.State]++
	}
	var out []string
	for _, p := range parts {
		if n := counts[p.state]; n > 0 {
			out = append(out, fmt.Sprintf("%d %s", n, p.words))
		}
	}
	return strings.Join(out, ", ")
}
