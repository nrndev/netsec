// Package hardening holds the pure logic behind WorkloadHardening: which workloads
// to touch, which fields to set, the apply configurations, the plan hash and the
// health gate. It never talks to a cluster.
package hardening

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MaxTargets is the most workloads one plan may patch (design §4.1).
const MaxTargets = 200

// ErrTooManyWorkloads is the TooManyWorkloads refusal.
var ErrTooManyWorkloads = errors.New("too many workloads")

// IgnoreLabel opts a namespace or a workload out of hardening.
const IgnoreLabel = "netsec.nrnx.dev/ignore"

// Candidate is a workload found in a target namespace.
// Kind is a string because Jobs and Pods are listed too, to be reported.
type Candidate struct {
	Kind            string
	Namespace       string
	Name            string
	Labels          map[string]string
	Annotations     map[string]string
	OwnerReferences []metav1.OwnerReference
	// NamespaceLabels are the labels of the workload's namespace.
	NamespaceLabels map[string]string
}

// Skip is a candidate we will report but never patch.
type Skip struct {
	Candidate Candidate
	Reason    string
}

// gitOpsMarkers are the labels and annotations that mean another tool owns the workload.
var gitOpsMarkers = []struct {
	annotation bool
	key, tool  string
}{
	{true, "argocd.argoproj.io/tracking-id", "Argo CD"},
	{false, "argocd.argoproj.io/instance", "Argo CD"},
	{false, "kustomize.toolkit.fluxcd.io/name", "Flux"},
	{false, "helm.toolkit.fluxcd.io/name", "Flux"},
}

// Classify splits candidates into targets and skipped workloads (design §4.1).
// protected lists namespaces we never touch; names starting with "kube-" are always protected.
// More than MaxTargets targets is an error wrapping ErrTooManyWorkloads.
func Classify(candidates []Candidate, protected []string) (targets []Candidate, skipped []Skip, err error) {
	for _, c := range candidates {
		if reason := SkipReason(c, protected); reason != "" {
			skipped = append(skipped, Skip{Candidate: c, Reason: reason})
			continue
		}
		targets = append(targets, c)
	}
	if len(targets) > MaxTargets {
		return nil, nil, fmt.Errorf("%w: %d targets, the limit is %d; narrow namespaces or selector", ErrTooManyWorkloads, len(targets), MaxTargets)
	}
	return targets, skipped, nil
}

// SkipReason says why a workload must not be patched, or "" if it may be. The plan and
// the patch step both use it, so a label added after approval is still honoured.
func SkipReason(c Candidate, protected []string) string {
	switch {
	case strings.HasPrefix(c.Namespace, "kube-") || slices.Contains(protected, c.Namespace):
		return fmt.Sprintf("namespace %s is protected", c.Namespace)
	case c.NamespaceLabels[IgnoreLabel] == "true":
		return fmt.Sprintf("namespace %s is labelled %s=true", c.Namespace, IgnoreLabel)
	case c.Kind == "Job" || c.Kind == "Pod":
		return fmt.Sprintf("%s is report-only", c.Kind)
	case c.Labels[IgnoreLabel] == "true":
		return fmt.Sprintf("labelled %s=true", IgnoreLabel)
	}
	for _, o := range c.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			return fmt.Sprintf("owned by %s %s", o.Kind, o.Name)
		}
	}
	for _, m := range gitOpsMarkers {
		src := c.Labels
		if m.annotation {
			src = c.Annotations
		}
		if _, ok := src[m.key]; ok {
			return "managed by " + m.tool
		}
	}
	return ""
}
