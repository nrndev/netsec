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

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	netsecv1alpha1 "github.com/nrndev/netsec/api/v1alpha1"
)

// NetSec's own metrics (design §5). They sit on controller-runtime's registry, so the
// manager's metrics endpoint serves them next to the built-in reconcile metrics.
var (
	isolationReady = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "netsec_isolation_ready",
		Help: "1 when the NetworkIsolation is Ready, else 0.",
	}, []string{"isolation"})

	isolationRefusals = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "netsec_isolation_refusals_total",
		Help: "Times a NetworkIsolation moved into a not-ready reason.",
	}, []string{"reason"})

	hardeningWorkloads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "netsec_hardening_workloads_total",
		Help: "Times a workload reached a final state in a WorkloadHardening run.",
	}, []string{"result"})
)

func init() {
	metrics.Registry.MustRegister(isolationReady, isolationRefusals, hardeningWorkloads)
	// Show every counter series at 0 from the start, so a scrape and a rate() see them
	// before the first event.
	for reason := range refusalReasons {
		isolationRefusals.WithLabelValues(reason)
	}
	for state := range countedStates {
		hardeningWorkloads.WithLabelValues(string(state))
	}
}

// refusalReasons are the Ready=False reasons that count as a refusal.
var refusalReasons = map[string]bool{
	"ConflictingPolicy":        true,
	"PodCIDRUnknown":           true,
	"ProtectedNamespace":       true,
	"InvalidExtraAllowedCIDRs": true,
	reasonPodRangeMismatch:     true,
	"NamespaceMissing":         true,
}

// countedStates are the states that count as a workload's result.
var countedStates = map[netsecv1alpha1.WorkloadState]bool{
	netsecv1alpha1.StateHealthy:    true,
	netsecv1alpha1.StateUnverified: true,
	netsecv1alpha1.StateReverted:   true,
	netsecv1alpha1.StateFailed:     true,
	netsecv1alpha1.StateSkipped:    true,
	netsecv1alpha1.StateNoChange:   true,
	netsecv1alpha1.StateUndone:     true,
}

// countWorkloadResults adds one to the counter for each workload whose state changed to
// a counted state between old and cur. Workloads are matched by kind, namespace and name,
// so a workload that is new in cur is not counted.
func countWorkloadResults(old, cur []netsecv1alpha1.PlannedWorkload) {
	type key struct{ kind, ns, name string }
	was := make(map[key]netsecv1alpha1.WorkloadState, len(old))
	for _, w := range old {
		was[key{string(w.Kind), w.Namespace, w.Name}] = w.State
	}
	for _, w := range cur {
		prev, ok := was[key{string(w.Kind), w.Namespace, w.Name}]
		if ok && prev != w.State && countedStates[w.State] {
			hardeningWorkloads.WithLabelValues(string(w.State)).Inc()
		}
	}
}

// lastReason is the Ready reason last seen per isolation, by name. The reconciler reads
// from a cache that can still show the status from before its own write, so the status
// alone would count the same refusal twice.
var lastReason sync.Map

// noteReason records the reason and reports whether it is a refusal the isolation just
// moved into. fromStatus is the reason in the status read at the start of the pass; it
// is used only when this process has not seen the isolation yet, so a restart does not
// count refusals again.
func noteReason(name, reason, fromStatus string) bool {
	last := fromStatus
	if v, ok := lastReason.Swap(name, reason); ok {
		last = v.(string)
	}
	return refusalReasons[reason] && last != reason
}
