package hardening

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	nsApp          = "tenant-a"
	kindDep        = "Deployment"
	wordPrivileged = "privileged"
	initName       = "setup"
	keyAPE         = "allowPrivilegeEscalation"
	capSysAdmin    = "SYS_ADMIN"
	oomKilled      = "OOMKilled"
	didNotFinish   = "did not finish"
	crashLoop      = "CrashLoopBackOff"
)

func cand(mod func(*Candidate)) Candidate {
	c := Candidate{Kind: kindDep, Namespace: nsApp, Name: "web"}
	if mod != nil {
		mod(&c)
	}
	return c
}

func TestClassify(t *testing.T) {
	yes := true
	cases := []struct {
		name string
		c    Candidate
		want string // substring of the skip reason; "" means target
	}{
		{"plain workload is a target", cand(nil), ""},
		{"kube- namespace", cand(func(c *Candidate) { c.Namespace = "kube-system" }), "protected"},
		{"listed protected namespace", cand(func(c *Candidate) { c.Namespace = "netsec-system" }), "protected"},
		{"namespace opt-out", cand(func(c *Candidate) { c.NamespaceLabels = map[string]string{IgnoreLabel: "true"} }), "namespace tenant-a is labelled"},
		{"namespace label with another value", cand(func(c *Candidate) { c.NamespaceLabels = map[string]string{IgnoreLabel: "false"} }), ""},
		{"workload opt-out", cand(func(c *Candidate) { c.Labels = map[string]string{IgnoreLabel: "true"} }), "labelled"},
		{"controller owner", cand(func(c *Candidate) {
			c.OwnerReferences = []metav1.OwnerReference{{Kind: "Rollout", Name: "r", Controller: &yes}}
		}), "owned by Rollout r"},
		{"non-controller owner is fine", cand(func(c *Candidate) {
			c.OwnerReferences = []metav1.OwnerReference{{Kind: "Thing", Name: "t"}}
		}), ""},
		{"argo annotation", cand(func(c *Candidate) { c.Annotations = map[string]string{"argocd.argoproj.io/tracking-id": "x"} }), "Argo CD"},
		{"argo label", cand(func(c *Candidate) { c.Labels = map[string]string{"argocd.argoproj.io/instance": "x"} }), "Argo CD"},
		{"flux kustomize label", cand(func(c *Candidate) { c.Labels = map[string]string{"kustomize.toolkit.fluxcd.io/name": "x"} }), "Flux"},
		{"flux helm label", cand(func(c *Candidate) { c.Labels = map[string]string{"helm.toolkit.fluxcd.io/name": "x"} }), "Flux"},
		{"argo marker in the wrong place is ignored", cand(func(c *Candidate) { c.Labels = map[string]string{"argocd.argoproj.io/tracking-id": "x"} }), ""},
		{"Job is report-only", cand(func(c *Candidate) { c.Kind = "Job" }), "report-only"},
		{"bare Pod is report-only", cand(func(c *Candidate) { c.Kind = "Pod" }), "report-only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			targets, skipped, err := Classify([]Candidate{tc.c}, []string{"netsec-system"})
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if len(targets) != 1 || len(skipped) != 0 {
					t.Fatalf("targets=%d skipped=%+v, want one target", len(targets), skipped)
				}
				return
			}
			if len(targets) != 0 || len(skipped) != 1 || !strings.Contains(skipped[0].Reason, tc.want) {
				t.Fatalf("targets=%d skipped=%+v, want a skip containing %q", len(targets), skipped, tc.want)
			}
		})
	}
}

func many(n int) []Candidate {
	out := make([]Candidate, n)
	for i := range out {
		out[i] = cand(func(c *Candidate) { c.Name = fmt.Sprintf("w%d", i) })
	}
	return out
}

func TestClassifyTargetCap(t *testing.T) {
	if _, _, err := Classify(many(MaxTargets), nil); err != nil {
		t.Fatalf("%d targets should be allowed: %v", MaxTargets, err)
	}
	if _, _, err := Classify(many(MaxTargets+1), nil); !errors.Is(err, ErrTooManyWorkloads) {
		t.Fatalf("err = %v, want ErrTooManyWorkloads", err)
	}
	// Skipped workloads do not count towards the cap.
	cs := many(MaxTargets)
	for range 50 {
		cs = append(cs, cand(func(c *Candidate) { c.Kind = "Job" }))
	}
	if _, _, err := Classify(cs, nil); err != nil {
		t.Fatalf("skipped workloads must not count: %v", err)
	}
}
