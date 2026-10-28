// Package isolation holds the pure logic behind NetworkIsolation: the policy peers,
// the NetworkPolicy builders and the planner. It never talks to a cluster.
package isolation

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	networkingv1 "k8s.io/api/networking/v1"

	"github.com/nrndev/netsec/api/v1alpha1"
)

// nsNameLabel is set by Kubernetes on every namespace, with the namespace's name as value.
const nsNameLabel = "kubernetes.io/metadata.name"

// ErrNoPodCIDRs means no pod range is known, so no safe ipBlock can be built.
// The controller turns it into Refused/PodCIDRUnknown.
var ErrNoPodCIDRs = errors.New("no pod CIDRs are known")

// requirements turns a selector into one flat list: matchLabels become In requirements.
// The result is sorted by key so the output is stable.
func requirements(sel *metav1.LabelSelector) []metav1.LabelSelectorRequirement {
	keys := make([]string, 0, len(sel.MatchLabels))
	for k := range sel.MatchLabels {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	reqs := make([]metav1.LabelSelectorRequirement, 0, len(keys)+len(sel.MatchExpressions))
	for _, k := range keys {
		reqs = append(reqs, metav1.LabelSelectorRequirement{
			Key: k, Operator: metav1.LabelSelectorOpIn, Values: []string{sel.MatchLabels[k]},
		})
	}
	return append(reqs, sel.MatchExpressions...)
}

// negate flips one requirement (De Morgan). A pod that fails the requirement matches the result.
func negate(r metav1.LabelSelectorRequirement) (metav1.LabelSelectorRequirement, error) {
	out := *r.DeepCopy()
	switch r.Operator {
	case metav1.LabelSelectorOpIn:
		out.Operator = metav1.LabelSelectorOpNotIn
	case metav1.LabelSelectorOpNotIn:
		out.Operator = metav1.LabelSelectorOpIn
	case metav1.LabelSelectorOpExists:
		out.Operator = metav1.LabelSelectorOpDoesNotExist
	case metav1.LabelSelectorOpDoesNotExist:
		out.Operator = metav1.LabelSelectorOpExists
	default:
		return out, fmt.Errorf("requirement on key %q has unknown operator %q", r.Key, r.Operator)
	}
	return out, nil
}

// Complement returns peers that together match every pod except the group's pods.
func Complement(group v1alpha1.PodGroup) ([]networkingv1.NetworkPolicyPeer, error) {
	if len(group.Namespaces) == 0 {
		return nil, errors.New("group has no namespaces")
	}
	peers := []networkingv1.NetworkPolicyPeer{{
		NamespaceSelector: nsSelector(metav1.LabelSelectorOpNotIn, group.Namespaces),
	}}
	for _, r := range requirements(&group.PodSelector) {
		if (r.Operator == metav1.LabelSelectorOpIn || r.Operator == metav1.LabelSelectorOpNotIn) && len(r.Values) == 0 {
			return nil, fmt.Errorf("requirement on key %q uses %s with no values", r.Key, r.Operator)
		}
		n, err := negate(r)
		if err != nil {
			return nil, err
		}
		peers = append(peers, networkingv1.NetworkPolicyPeer{
			NamespaceSelector: nsSelector(metav1.LabelSelectorOpIn, group.Namespaces),
			PodSelector:       &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{n}},
		})
	}
	return peers, nil
}

func nsSelector(op metav1.LabelSelectorOperator, namespaces []string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: nsNameLabel, Operator: op, Values: append([]string(nil), namespaces...),
	}}}
}

// AllExcept is Complement plus one ipBlock per IP family that has known pod ranges.
// The ipBlock keeps nodes and outside clients working; its except list keeps pod IPs out.
// podCIDRs must be the whole cluster's pod range, so a pod on a node we have not seen yet
// is still excluded.
//
// extra are addresses inside the pod range that must still be let in, such as flannel's
// flannel.1 or Calico's tunnel addresses (--extra-allowed-cidrs). Each one becomes its own
// ipBlock peer, sorted and without duplicates. CheckExtraAllowed rejects any that would let
// pods back in.
func AllExcept(group v1alpha1.PodGroup, podCIDRs, extra []string) ([]networkingv1.NetworkPolicyPeer, error) {
	if len(podCIDRs) == 0 {
		return nil, ErrNoPodCIDRs
	}
	if err := CheckExtraAllowed(extra, podCIDRs); err != nil {
		return nil, err
	}
	var v4, v6, extras []string
	for _, c := range podCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("pod CIDR %q is not valid: %w", c, err)
		}
		p = p.Masked()
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	for _, c := range extra {
		extras = append(extras, netip.MustParsePrefix(c).Masked().String()) // CheckExtraAllowed parsed it
	}
	peers, err := Complement(group)
	if err != nil {
		return nil, err
	}
	if len(v4) > 0 {
		peers = append(peers, ipBlock("0.0.0.0/0", v4))
	}
	if len(v6) > 0 {
		peers = append(peers, ipBlock("::/0", v6))
	}
	slices.Sort(extras)
	for _, e := range slices.Compact(extras) {
		peers = append(peers, networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: e}})
	}
	return peers, nil
}

// CheckExtraAllowed rejects an extra-allowed entry that is not a CIDR, or that overlaps a
// pod range without being a single address (/32 or /128). A wider block inside the pod
// range would let the isolated group's pods back in.
func CheckExtraAllowed(extra, podRanges []string) error {
	ranges := make([]netip.Prefix, 0, len(podRanges))
	for _, c := range podRanges {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("pod CIDR %q is not valid: %w", c, err)
		}
		ranges = append(ranges, p)
	}
	for _, c := range extra {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("extra allowed CIDR %q is not valid: %w", c, err)
		}
		if p.Bits() == p.Addr().BitLen() {
			continue
		}
		for _, r := range ranges {
			if r.Overlaps(p) {
				return fmt.Errorf("extra allowed CIDR %q overlaps pod range %s and is not a single address (use /32 or /128); it would let pods in", c, r)
			}
		}
	}
	return nil
}

func ipBlock(cidr string, except []string) networkingv1.NetworkPolicyPeer {
	slices.Sort(except)
	return networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr, Except: slices.Compact(except)}}
}

// MayOverlap returns false only when some label key has requirements that no pod can
// satisfy together. Otherwise it returns true, to be safe.
func MayOverlap(a, b *metav1.LabelSelector) bool {
	byKey := map[string][]metav1.LabelSelectorRequirement{}
	for _, r := range append(requirements(a), requirements(b)...) {
		byKey[r.Key] = append(byKey[r.Key], r)
	}
	for _, reqs := range byKey {
		if !satisfiable(reqs) {
			return false
		}
	}
	return true
}

// satisfiable says whether one label (a value, or no label) can meet every requirement.
// Unknown operators are ignored, which errs towards "may overlap".
func satisfiable(reqs []metav1.LabelSelectorRequirement) bool {
	var mustExist, mustBeAbsent bool
	var allowed map[string]bool // nil until the first In; then the values still possible
	banned := map[string]bool{}
	for _, r := range reqs {
		switch r.Operator {
		case metav1.LabelSelectorOpExists:
			mustExist = true
		case metav1.LabelSelectorOpDoesNotExist:
			mustBeAbsent = true
		case metav1.LabelSelectorOpNotIn:
			for _, v := range r.Values {
				banned[v] = true
			}
		case metav1.LabelSelectorOpIn:
			mustExist = true
			next := map[string]bool{}
			for _, v := range r.Values {
				if allowed == nil || allowed[v] {
					next[v] = true
				}
			}
			allowed = next
		}
	}
	if mustBeAbsent {
		return !mustExist
	}
	if allowed == nil {
		return true // any value, or no label, works
	}
	for v := range allowed {
		if !banned[v] {
			return true
		}
	}
	return false
}
