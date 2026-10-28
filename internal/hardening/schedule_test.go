package hardening

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/nrndev/netsec/api/v1alpha1"
)

func states(ss ...v1alpha1.WorkloadState) []v1alpha1.PlannedWorkload {
	out := make([]v1alpha1.PlannedWorkload, 0, len(ss))
	for i, s := range ss {
		out = append(out, v1alpha1.PlannedWorkload{Name: fmt.Sprint(i), State: s})
	}
	return out
}

func TestNextToStart(t *testing.T) {
	const P, A, H, S = v1alpha1.StatePending, v1alpha1.StateApplying, v1alpha1.StateHealthy, v1alpha1.StateSkipped
	pending := []v1alpha1.WorkloadState{P}
	tests := []struct {
		name string
		ws   []v1alpha1.PlannedWorkload
		max  int
		want []int
	}{
		{"takes pending in plan order", states(S, P, P, P), 2, []int{1, 2}},
		{"in-flight workloads use up slots", states(A, P, P), 2, []int{1}},
		{"no free slot", states(A, P), 1, nil},
		{"over-full never goes negative", states(A, A, P), 1, nil},
		{"nothing pending", states(H, S), 3, nil},
		{"empty plan", nil, 1, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NextToStart(tt.ws, pending, A, tt.max); !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestActiveSet(t *testing.T) {
	run := func(uid, name string, phase v1alpha1.HardeningPhase, state v1alpha1.WorkloadState) v1alpha1.WorkloadHardening {
		wh := v1alpha1.WorkloadHardening{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("uid-" + uid)}}
		wh.Status.Phase = phase
		wh.Status.Plan = &v1alpha1.HardeningPlan{Workloads: []v1alpha1.PlannedWorkload{
			{Kind: v1alpha1.KindDeployment, Namespace: "ns", Name: name, State: state}}}
		return wh
	}
	runs := []v1alpha1.WorkloadHardening{
		run("self", "mine", v1alpha1.PhaseApplying, v1alpha1.StatePending),
		run("o1", "pending", v1alpha1.PhaseApplying, v1alpha1.StatePending),
		run("o2", "undoing", v1alpha1.PhaseUndoing, v1alpha1.StateUndoing),
		run("o3", "healthy", v1alpha1.PhaseApplying, v1alpha1.StateHealthy),
		run("o4", "planned", v1alpha1.PhasePlanned, v1alpha1.StatePending),
	}
	got := ActiveSet(runs, "uid-self")
	want := map[string]string{"Deployment/ns/pending": "pending", "Deployment/ns/undoing": "undoing"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
}

func TestRejection(t *testing.T) {
	gr := schema.GroupResource{Group: "apps", Resource: "deployments"}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"invalid", apierrors.NewInvalid(schema.GroupKind{Group: "apps", Kind: "Deployment"}, "x", nil), true},
		{"conflict", apierrors.NewConflict(gr, "x", errors.New("owned by kubectl")), true},
		{"forbidden", apierrors.NewForbidden(gr, "x", errors.New("no")), true},
		{"wrapped", fmt.Errorf("apply: %w", apierrors.NewBadRequest("bad")), true},
		{"server error", apierrors.NewInternalError(errors.New("boom")), false},
		{"timeout", apierrors.NewServerTimeout(gr, "patch", 1), false},
		{"too many requests", apierrors.NewTooManyRequests("slow down", 1), false},
		{"not an api error", errors.New("connection refused"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, ok := Rejection(tt.err)
			if ok != tt.want || (ok && msg == "") {
				t.Errorf("got (%q, %v), want %v", msg, ok, tt.want)
			}
		})
	}
}

func TestSummary(t *testing.T) {
	mk := func(states ...v1alpha1.WorkloadState) []v1alpha1.PlannedWorkload {
		ws := make([]v1alpha1.PlannedWorkload, 0, len(states))
		for _, s := range states {
			ws = append(ws, v1alpha1.PlannedWorkload{State: s})
		}
		return ws
	}
	cases := []struct {
		name  string
		phase v1alpha1.HardeningPhase
		ws    []v1alpha1.PlannedWorkload
		want  string
	}{
		{"planned", v1alpha1.PhasePlanned, mk("Pending", "Pending", "Pending", "Skipped", "Skipped", "NoChange", "Failed"), "3 to change, 2 skipped, 1 already hardened, 1 would fail"},
		{"planned leaves out zeros", v1alpha1.PhasePlanned, mk("Pending", "NoChange"), "1 to change, 1 already hardened"},
		{"planned with nothing", v1alpha1.PhasePlanned, nil, "no workloads matched"},
		{"applying", v1alpha1.PhaseApplying, mk("Applying", "Healthy", "Healthy", "Pending"), "1 rolling out, 2 healthy, 1 waiting"},
		{"completed", v1alpha1.PhaseCompleted, mk("Healthy", "Healthy", "Healthy", "Reverted", "Skipped"), "3 healthy, 1 reverted"},
		{"failed run", v1alpha1.PhaseFailed, mk("Healthy", "Failed"), "1 healthy, 1 failed"},
		{"undoing", v1alpha1.PhaseUndoing, mk("Undone", "Undone", "Undoing"), "2 undone, 1 undoing"},
		{"unknown phase", "", mk("Pending"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Summary(c.phase, c.ws); got != c.want {
				t.Errorf("summary = %q, want %q", got, c.want)
			}
		})
	}
}

func TestClaimName(t *testing.T) {
	a := ClaimName(v1alpha1.KindDeployment, "ns", "web")
	if !regexp.MustCompile(`^netsec-claim-[0-9a-f]{16}$`).MatchString(a) {
		t.Errorf("name %q is not netsec-claim-<16 hex>", a)
	}
	if a != ClaimName(v1alpha1.KindDeployment, "ns", "web") {
		t.Error("the same workload must always get the same name")
	}
	for _, other := range []string{ClaimName(v1alpha1.KindStatefulSet, "ns", "web"), ClaimName(v1alpha1.KindDeployment, "ns2", "web"), ClaimName(v1alpha1.KindDeployment, "ns", "web2")} {
		if other == a {
			t.Errorf("different workloads share the name %q", a)
		}
	}
}

func TestHasApplied(t *testing.T) {
	const P, A, H, S, N, F, R = v1alpha1.StatePending, v1alpha1.StateApplying, v1alpha1.StateHealthy,
		v1alpha1.StateSkipped, v1alpha1.StateNoChange, v1alpha1.StateFailed, v1alpha1.StateReverted
	at := metav1.Now()
	tests := []struct {
		name string
		ws   []v1alpha1.PlannedWorkload
		want bool
	}{
		{"fresh plan", states(P, N, S), false},
		{"a plan-time WouldFail is not an apply", states(P, F), false},
		{"empty", nil, false},
		{"applying", states(P, A), true},
		{"healthy", states(H), true},
		{"reverted", states(R), true},
		{"failed after a patch", []v1alpha1.PlannedWorkload{{State: F, AppliedAt: &at}}, true},
		{"pending with appliedAt", []v1alpha1.PlannedWorkload{{State: P, AppliedAt: &at}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasApplied(tt.ws); got != tt.want {
				t.Errorf("HasApplied = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNeedsPlan(t *testing.T) {
	for _, tt := range []struct {
		havePlan      bool
		observed, gen int64
		want          bool
	}{
		{false, 0, 1, true}, {false, 1, 1, true}, {true, 1, 1, false}, {true, 1, 2, true},
	} {
		if got := NeedsPlan(tt.havePlan, tt.observed, tt.gen); got != tt.want {
			t.Errorf("NeedsPlan(%v, %d, %d) = %v, want %v", tt.havePlan, tt.observed, tt.gen, got, tt.want)
		}
	}
}

func TestRevertExpired(t *testing.T) {
	applied := metav1.NewTime(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	const timeout = 10 * time.Minute
	for _, tt := range []struct {
		name string
		at   *metav1.Time
		now  time.Time
		want bool
	}{
		{"just applied", &applied, applied.Add(time.Minute), false},
		{"at the rollout timeout", &applied, applied.Add(timeout), false},
		{"just under twice the timeout", &applied, applied.Add(2*timeout - time.Second), false},
		{"exactly twice the timeout", &applied, applied.Add(2 * timeout), false},
		{"past twice the timeout", &applied, applied.Add(2*timeout + time.Second), true},
		{"no appliedAt never expires", nil, applied.Add(100 * timeout), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := RevertExpired(tt.at, tt.now, timeout); got != tt.want {
				t.Errorf("RevertExpired = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyTime(t *testing.T) {
	const ours = "ours"
	old, newer := metav1.NewTime(time.Unix(100, 0)), metav1.NewTime(time.Unix(200, 0))
	fields := []metav1.ManagedFieldsEntry{
		{Manager: ours, Operation: metav1.ManagedFieldsOperationUpdate, Time: &old},
		{Manager: "theirs", Operation: metav1.ManagedFieldsOperationApply, Time: &old},
		{Manager: ours, Operation: metav1.ManagedFieldsOperationApply, Time: &newer},
	}
	if got, ok := ApplyTime(fields, ours); !ok || !got.Equal(&newer) {
		t.Errorf("ApplyTime = %v, %v; want %v, true", got, ok, newer)
	}
	if _, ok := ApplyTime(fields[:2], ours); ok {
		t.Error("an Update entry or another manager's Apply entry must not count")
	}
	if _, ok := ApplyTime([]metav1.ManagedFieldsEntry{{Manager: ours, Operation: metav1.ManagedFieldsOperationApply}}, ours); ok {
		t.Error("an entry without a time must not count")
	}
}
