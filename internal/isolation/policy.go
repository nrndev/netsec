package isolation

import (
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nrndev/netsec/api/v1alpha1"
)

const (
	// LabelManagedBy and LabelIsolationUID mark every policy we create.
	LabelManagedBy    = "app.kubernetes.io/managed-by"
	ManagedByValue    = "netsec"
	LabelIsolationUID = "netsec.nrnx.dev/isolation-uid"
	// AnnotationIsolation holds the NetworkIsolation's name (names can be too long for a label).
	AnnotationIsolation = "netsec.nrnx.dev/isolation"
)

const (
	kindIngress = "ingress"
	kindEgress  = "egress"
)

// GroupOf returns the group called name, or false if the isolation has none.
func GroupOf(iso *v1alpha1.NetworkIsolation, name string) (v1alpha1.PodGroup, bool) {
	for _, g := range iso.Spec.Between {
		if g.Name == name {
			return g, true
		}
	}
	return v1alpha1.PodGroup{}, false
}

// OtherGroup returns the group that is not called name.
func OtherGroup(iso *v1alpha1.NetworkIsolation, name string) (v1alpha1.PodGroup, bool) {
	for _, g := range iso.Spec.Between {
		if g.Name != name {
			return g, true
		}
	}
	return v1alpha1.PodGroup{}, false
}

// Policies builds the NetworkPolicies for the direction from -> the other group, one per
// namespace of the group that carries the policy:
//   - IngressPolicy: on the receiving group, allow from everything except the sending group.
//   - EgressPolicy: on the sending group, allow to everything except the receiving group.
//
// from is the name of the sending group. podCIDRs is the cluster-wide pod range and
// extra the extra allowed addresses (see AllExcept).
func Policies(iso *v1alpha1.NetworkIsolation, from string, mech v1alpha1.Mechanism, podCIDRs, extra []string) ([]networkingv1.NetworkPolicy, error) {
	uid := string(iso.UID)
	if len(uid) < 8 {
		return nil, fmt.Errorf("NetworkIsolation %q has uid %q; need at least 8 characters", iso.Name, uid)
	}
	if len(iso.Spec.Between) != 2 {
		return nil, fmt.Errorf("NetworkIsolation %q has %d groups; need exactly 2", iso.Name, len(iso.Spec.Between))
	}
	sender, ok := GroupOf(iso, from)
	if !ok {
		return nil, fmt.Errorf("NetworkIsolation %q has no group %q", iso.Name, from)
	}
	receiver, _ := OtherGroup(iso, from)
	var held, peerGroup v1alpha1.PodGroup
	var kind string
	switch mech {
	case v1alpha1.MechanismIngressPolicy:
		held, peerGroup, kind = receiver, sender, kindIngress
	case v1alpha1.MechanismEgressPolicy:
		held, peerGroup, kind = sender, receiver, kindEgress
	default:
		return nil, fmt.Errorf("cannot build policies for mechanism %q", mech)
	}
	peers, err := AllExcept(peerGroup, podCIDRs, extra)
	if err != nil {
		return nil, fmt.Errorf("build peers for %s of %q: %w", kind, iso.Name, err)
	}

	pol := networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: policyName(uid, kind, held.Name),
			Labels: map[string]string{
				LabelManagedBy:    ManagedByValue,
				LabelIsolationUID: uid,
			},
			Annotations: map[string]string{AnnotationIsolation: iso.Name},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         v1alpha1.GroupVersion.String(),
				Kind:               "NetworkIsolation",
				Name:               iso.Name,
				UID:                iso.UID,
				Controller:         new(true),
				BlockOwnerDeletion: new(true),
			}},
		},
		Spec: networkingv1.NetworkPolicySpec{PodSelector: *held.PodSelector.DeepCopy()},
	}
	if kind == kindIngress {
		pol.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
		pol.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{From: peers}}
	} else {
		pol.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
		pol.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{To: peers}}
	}

	out := make([]networkingv1.NetworkPolicy, 0, len(held.Namespaces))
	for _, ns := range held.Namespaces {
		p := *pol.DeepCopy()
		p.Namespace = ns
		out = append(out, p)
	}
	return out, nil
}

// policyName is netsec-<first 8 of uid>-<group name>-<ingress|egress>. uid must have 8 or more characters.
func policyName(uid, kind, group string) string {
	return fmt.Sprintf("netsec-%s-%s-%s", uid[:8], group, kind)
}
