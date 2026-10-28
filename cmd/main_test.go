package main

import (
	"slices"
	"testing"
)

func TestWithAlwaysProtected(t *testing.T) {
	const own = "ops"
	t.Setenv("POD_NAMESPACE", own)
	for name, in := range map[string][]string{
		"empty flag":         nil,
		"unrelated only":     {"prod"},
		"already has own ns": {own, "prod"},
	} {
		got := withAlwaysProtected(in)
		for _, want := range append([]string{own, "kube-system", "kube-public", "kube-node-lease"}, in...) {
			if !slices.Contains(got, want) {
				t.Errorf("%s: %v is missing %q", name, got, want)
			}
		}
	}
	got := slices.Sorted(slices.Values(withAlwaysProtected([]string{own})))
	if len(slices.Compact(slices.Clone(got))) != len(got) {
		t.Errorf("duplicates in %v", got)
	}
}
