package isolation

import (
	"fmt"
	"slices"

	networkingv1 "k8s.io/api/networking/v1"

	"github.com/nrndev/netsec/api/v1alpha1"
)

// Refused is the planner's answer when no mechanism is safe.
// NOTE(design): it is not a valid status value (the API enum has two values),
// so the controller must map it to a Ready=False condition and never write it to status.
const Refused v1alpha1.Mechanism = "Refused"

// Plan is the planner's answer for one direction.
type Plan struct {
	Mechanism v1alpha1.Mechanism
	// Conflicts lists the "namespace/name" of other policies that block both
	// mechanisms. Only set when Mechanism is Refused.
	Conflicts []string
}

// PlanDirection picks how to block traffic from -> to (design §3.2).
//
// policies are all NetworkPolicies in the namespaces of both groups. Ours (by
// IsOwn) are ignored; every other policy counts. current is the
// mechanism chosen last time, or "" if none: it is kept while it stays valid.
func PlanDirection(iso *v1alpha1.NetworkIsolation, from, to v1alpha1.PodGroup, policies []networkingv1.NetworkPolicy, current v1alpha1.Mechanism) Plan {
	var others []networkingv1.NetworkPolicy
	for _, p := range policies {
		if !IsOwn(p, iso) {
			others = append(others, p)
		}
	}
	ingress := conflicts(others, to, networkingv1.PolicyTypeIngress)
	egress := conflicts(others, from, networkingv1.PolicyTypeEgress)

	switch {
	case current == v1alpha1.MechanismEgressPolicy && len(egress) == 0:
		return Plan{Mechanism: v1alpha1.MechanismEgressPolicy}
	case len(ingress) == 0:
		return Plan{Mechanism: v1alpha1.MechanismIngressPolicy}
	case len(egress) == 0:
		return Plan{Mechanism: v1alpha1.MechanismEgressPolicy}
	}
	all := append(ingress, egress...)
	slices.Sort(all)
	return Plan{Mechanism: Refused, Conflicts: all}
}

// IsOwn says whether p is a policy of this isolation. The label alone is not enough:
// a tenant can copy it onto their own policy. So the name must also be one this spec
// generates now, or one listed in status.traffic[].policies (as namespace/name).
// The status entries cover policies from before an edit, such as a renamed group, so the
// planner does not mistake them for conflicts and cleanup can delete them. Only the
// operator writes status, so a tenant cannot add entries there.
func IsOwn(p networkingv1.NetworkPolicy, iso *v1alpha1.NetworkIsolation) bool {
	uid := string(iso.UID)
	if len(uid) < 8 || p.Labels[LabelIsolationUID] != uid {
		return false
	}
	// A generated name counts only in a namespace of the group that holds the policy.
	for _, kind := range []string{kindIngress, kindEgress} {
		for _, g := range iso.Spec.Between {
			if p.Name == policyName(uid, kind, g.Name) && slices.Contains(g.Namespaces, p.Namespace) {
				return true
			}
		}
	}
	key := p.Namespace + "/" + p.Name
	for _, t := range iso.Status.Traffic {
		if slices.Contains(t.Policies, key) {
			return true
		}
	}
	return false
}

// conflicts lists policies of the given type that sit in one of the group's
// namespaces and may select the group's pods.
func conflicts(policies []networkingv1.NetworkPolicy, group v1alpha1.PodGroup, t networkingv1.PolicyType) []string {
	var out []string
	for _, p := range policies {
		if !slices.Contains(group.Namespaces, p.Namespace) || !hasType(p, t) {
			continue
		}
		if MayOverlap(&p.Spec.PodSelector, &group.PodSelector) {
			out = append(out, fmt.Sprintf("%s/%s", p.Namespace, p.Name))
		}
	}
	return out
}

// hasType says whether the policy governs the given direction. The API server fills
// policyTypes in; if it is empty we apply the same default: Ingress always, Egress
// when egress rules exist.
func hasType(p networkingv1.NetworkPolicy, t networkingv1.PolicyType) bool {
	if len(p.Spec.PolicyTypes) == 0 {
		return t == networkingv1.PolicyTypeIngress || len(p.Spec.Egress) > 0
	}
	return slices.Contains(p.Spec.PolicyTypes, t)
}
