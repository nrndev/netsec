package hardening

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/nrndev/netsec/api/v1alpha1"
)

// PlanHash is the first 16 hex characters of a sha256 over the sorted
// (kind, namespace, name, generation, changes) of every workload (design §4.3).
// It does not depend on input order, and ignores state and reason.
// Callers pass only the workloads that will be patched.
func PlanHash(workloads []v1alpha1.PlannedWorkload) string {
	type entry struct {
		Kind       v1alpha1.WorkloadKind
		Namespace  string
		Name       string
		Generation int64
		Changes    []string
	}
	entries := make([]entry, len(workloads))
	for i, w := range workloads {
		changes := slices.Clone(w.Changes)
		slices.Sort(changes)
		entries[i] = entry{w.Kind, w.Namespace, w.Name, w.Generation, changes}
	}
	slices.SortFunc(entries, func(a, b entry) int {
		return cmp.Or(
			cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Namespace, b.Namespace),
			cmp.Compare(a.Name, b.Name),
		)
	})
	// Marshalling plain structs and strings cannot fail.
	data, _ := json.Marshal(entries)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:16]
}
