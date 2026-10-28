package hardening

import (
	"testing"

	"github.com/nrndev/netsec/api/v1alpha1"
)

func planned(name string, gen int64, changes ...string) v1alpha1.PlannedWorkload {
	return v1alpha1.PlannedWorkload{Kind: v1alpha1.KindDeployment, Namespace: nsApp, Name: name, Generation: gen, Changes: changes}
}

func TestPlanHash(t *testing.T) {
	a, b := planned("a", 1, "x: <unset> → 1", "y: <unset> → 2"), planned("b", 2, "z: <unset> → 3")
	base := PlanHash([]v1alpha1.PlannedWorkload{a, b})
	if len(base) != 16 {
		t.Fatalf("hash %q is not 16 characters", base)
	}
	if got := PlanHash([]v1alpha1.PlannedWorkload{b, a}); got != base {
		t.Errorf("workload order changed the hash: %s vs %s", got, base)
	}
	if got := PlanHash([]v1alpha1.PlannedWorkload{planned("a", 1, "y: <unset> → 2", "x: <unset> → 1"), b}); got != base {
		t.Errorf("change order changed the hash")
	}
	// State and reason are not part of the hash.
	c := a
	c.State, c.Reason = v1alpha1.StateFailed, "WouldFail"
	if got := PlanHash([]v1alpha1.PlannedWorkload{c, b}); got != base {
		t.Errorf("state changed the hash")
	}
	differs := map[string][]v1alpha1.PlannedWorkload{
		"generation": {planned("a", 2, "x: <unset> → 1", "y: <unset> → 2"), b},
		"change":     {planned("a", 1, "x: <unset> → 1"), b},
		"name":       {planned("c", 1, "x: <unset> → 1", "y: <unset> → 2"), b},
		"missing":    {a},
	}
	for name, ws := range differs {
		if PlanHash(ws) == base {
			t.Errorf("a different %s kept the hash", name)
		}
	}
	// "ab"+"c" must not collide with "a"+"bc".
	if PlanHash([]v1alpha1.PlannedWorkload{planned("w", 1, "ab", "c")}) == PlanHash([]v1alpha1.PlannedWorkload{planned("w", 1, "a", "bc")}) {
		t.Error("change boundaries collide")
	}
}
