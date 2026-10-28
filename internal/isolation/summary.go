package isolation

import (
	"fmt"
	"strings"

	"github.com/nrndev/netsec/api/v1alpha1"
)

// Summary is the one-line answer shown in status.summary and `kubectl get iso`.
// traffic holds both directions. notEnforced, when set, is why nothing is being
// enforced right now (for example "pod ranges unknown") and wins over traffic.
// pods are the group pod counts; a group with none is named, so a typo'd selector shows.
func Summary(traffic []v1alpha1.Traffic, pods []v1alpha1.GroupPods, notEnforced string) string {
	if notEnforced != "" {
		for _, t := range traffic {
			if t.Blocked {
				return Summary(traffic, pods, "") + " (edit not applied: " + notEnforced + ")"
			}
		}
		return "not enforced: " + notEnforced
	}
	if len(traffic) != 2 {
		return "not enforced: no traffic planned yet"
	}
	t0, t1 := traffic[0], traffic[1]
	switch {
	case t0.Blocked && t1.Blocked:
		return fmt.Sprintf("%s ⇄ %s: blocked both ways%s", t0.From, t0.To, noPodsNote(pods))
	case t0.Blocked || t1.Blocked:
		blocked, open := t0, t1
		if t1.Blocked {
			blocked, open = t1, t0
		}
		return fmt.Sprintf("%s → %s blocked; %s → %s NOT blocked (conflicting policy)", blocked.From, blocked.To, open.From, open.To)
	}
	return fmt.Sprintf("%s ⇄ %s: NOT blocked (conflicting policy)", t0.From, t0.To)
}

// noPodsNote returns " (a matches no pods)" or " (a, b match no pods)", or "" if every group has pods.
func noPodsNote(pods []v1alpha1.GroupPods) string {
	var empty []string
	for _, g := range pods {
		if g.Count == 0 {
			empty = append(empty, g.Group)
		}
	}
	switch len(empty) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf(" (%s matches no pods)", empty[0])
	}
	return fmt.Sprintf(" (%s match no pods)", strings.Join(empty, ", "))
}

// WithMismatch appends " (N pods outside the pod range)" to a summary when n > 0.
func WithMismatch(summary string, n int) string {
	switch {
	case n == 1:
		return summary + " (1 pod outside the pod range)"
	case n > 1:
		return fmt.Sprintf("%s (%d pods outside the pod range)", summary, n)
	}
	return summary
}
