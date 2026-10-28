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
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	netsecv1alpha1 "github.com/nrndev/netsec/api/v1alpha1"
)

// protectedNS is on the manager's --protected-namespaces list but does not start with kube-.
const (
	protectedNS  = "netsec-protected"
	gatewayApp   = "gateway"
	dashboardApp = "dashboard"
)

var _ = Describe("NetworkIsolation controller", func() {
	var (
		n       int // makes every spec's names unique: envtest cannot finish deleting a namespace
		nsA     string
		nsB     string
		isoName string
		stopMgr func()
	)

	BeforeEach(func() {
		SetDefaultEventuallyTimeout(20 * time.Second)
		SetDefaultEventuallyPollingInterval(100 * time.Millisecond)
		n++
		nsA, nsB, isoName = fmt.Sprintf("a%d", n), fmt.Sprintf("b%d", n), fmt.Sprintf("iso-%d", n)
		Expect(k8sClient.DeleteAllOf(ctx, &corev1.Node{})).To(Succeed())
		createNode("node-1", node1CIDR)
		stopMgr = startManager(nil)
	})

	AfterEach(func() {
		// The finalizer needs the controller, so delete while it still runs.
		Expect(k8sClient.DeleteAllOf(ctx, &netsecv1alpha1.NetworkIsolation{})).To(Succeed())
		Eventually(func() (int, error) {
			l := &netsecv1alpha1.NetworkIsolationList{}
			err := k8sClient.List(ctx, l)
			return len(l.Items), err
		}).Should(BeZero())
		stopMgr()
	})

	// newIso creates an isolation: the gateway group is app=gateway in nsA, the dashboard group is app=dashboard in nsB.
	newIso := func() *netsecv1alpha1.NetworkIsolation {
		iso := &netsecv1alpha1.NetworkIsolation{
			ObjectMeta: metav1.ObjectMeta{Name: isoName},
			Spec: netsecv1alpha1.NetworkIsolationSpec{
				Between: []netsecv1alpha1.PodGroup{
					{Name: gatewayApp, Namespaces: []string{nsA}, PodSelector: labelSel(appLabel, gatewayApp)},
					{Name: dashboardApp, Namespaces: []string{nsB}, PodSelector: labelSel(appLabel, dashboardApp)},
				},
			},
		}
		Expect(k8sClient.Create(ctx, iso)).To(Succeed())
		return iso
	}
	waitCond := func(typ, reason string) *netsecv1alpha1.NetworkIsolation {
		iso := &netsecv1alpha1.NetworkIsolation{}
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: isoName}, iso)).To(Succeed())
			c := meta.FindStatusCondition(iso.Status.Conditions, typ)
			g.Expect(c).NotTo(BeNil())
			g.Expect(c.Reason).To(Equal(reason))
			g.Expect(c.ObservedGeneration).To(Equal(iso.Generation))
		}).Should(Succeed(), "condition %s=%s", typ, reason)
		return iso
	}
	// mechanisms maps each blocked direction's sending group to what blocks it.
	mechanisms := func(iso *netsecv1alpha1.NetworkIsolation) map[string]netsecv1alpha1.Mechanism {
		out := map[string]netsecv1alpha1.Mechanism{}
		for _, t := range iso.Status.Traffic {
			if t.Blocked {
				out[t.From] = t.BlockedBy
			}
		}
		return out
	}
	policyName := func(iso *netsecv1alpha1.NetworkIsolation, kind, group string) string {
		return fmt.Sprintf("netsec-%s-%s-%s", iso.UID[:8], group, kind)
	}
	exists := func(ns, name string) func() error {
		return func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &networkingv1.NetworkPolicy{})
		}
	}
	ownPolicies := func(iso *netsecv1alpha1.NetworkIsolation) []networkingv1.NetworkPolicy {
		l := &networkingv1.NetworkPolicyList{}
		Expect(k8sClient.List(ctx, l, client.MatchingLabels{uidLabel: string(iso.UID)})).To(Succeed())
		return l.Items
	}
	hasEvent := func(reason string) {
		Eventually(func() (bool, error) {
			l := &eventsv1.EventList{}
			if err := k8sClient.List(ctx, l); err != nil {
				return false, err
			}
			for _, e := range l.Items {
				if e.Regarding.Name == isoName && e.Reason == reason {
					return true, nil
				}
			}
			return false, nil
		}).Should(BeTrue(), "event %s", reason)
	}

	It("creates policies for both directions and reports Ready", func() {
		createNS(nsA)
		createNS(nsB)
		createPod(nsA, "gw-1", map[string]string{appLabel: gatewayApp}, false)
		createPod(nsA, "gw-2", map[string]string{appLabel: gatewayApp}, false)
		createPod(nsA, "other", map[string]string{appLabel: "other"}, false)
		createPod(nsB, "dash-1", map[string]string{appLabel: dashboardApp}, false)
		newIso()

		iso := waitCond("Ready", "Enforced")
		Expect(meta.FindStatusCondition(iso.Status.Conditions, "Ready").Status).To(Equal(metav1.ConditionTrue))
		Expect(mechanisms(iso)).To(Equal(map[string]netsecv1alpha1.Mechanism{
			gatewayApp: netsecv1alpha1.MechanismIngressPolicy, dashboardApp: netsecv1alpha1.MechanismIngressPolicy,
		}))
		Expect(iso.Status.Summary).To(Equal("gateway ⇄ dashboard: blocked both ways"))
		waitEvent(isoName, "PolicyApplied", corev1.EventTypeNormal)
		Expect(iso.Status.Pods).To(Equal([]netsecv1alpha1.GroupPods{{Group: gatewayApp, Count: 2}, {Group: dashboardApp, Count: 1}}))
		Expect(iso.Status.Traffic[0].Policies).To(ConsistOf(nsB + "/" + policyName(iso, "ingress", "dashboard")))
		Expect(iso.Status.Traffic[1].Policies).To(ConsistOf(nsA + "/" + policyName(iso, "ingress", "gateway")))
		// The manager has no --pod-cidrs here, so the range came from the Nodes.
		deg := meta.FindStatusCondition(iso.Status.Conditions, "Degraded")
		Expect(deg.Status).To(Equal(metav1.ConditionTrue))
		Expect(deg.Reason).To(Equal("PodRangeFromNodes"))
		Expect(deg.Message).To(ContainSubstring("set --pod-cidrs"))

		for ns, on := range map[string]string{nsB: dashboardApp, nsA: gatewayApp} {
			p := &networkingv1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: policyName(iso, "ingress", on)}, p)).To(Succeed())
			Expect(p.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "netsec"))
			Expect(p.Labels).To(HaveKeyWithValue("netsec.nrnx.dev/isolation-uid", string(iso.UID)))
			Expect(p.Annotations).To(HaveKeyWithValue("netsec.nrnx.dev/isolation", isoName))
			Expect(p.OwnerReferences).To(HaveLen(1))
			Expect(p.OwnerReferences[0].UID).To(Equal(iso.UID))
			Expect(*p.OwnerReferences[0].Controller).To(BeTrue())
			Expect(p.Spec.PolicyTypes).To(Equal([]networkingv1.PolicyType{networkingv1.PolicyTypeIngress}))
			Expect(p.Spec.Ingress).To(HaveLen(1))
			from := p.Spec.Ingress[0].From
			// No extras are set, so the except block is last: no automatic tunnel address.
			Expect(from[len(from)-1].IPBlock.Except).To(Equal([]string{node1CIDR}))
		}
	})

	It("refuses without pod ranges, and the --pod-cidrs flag fixes it", func() {
		Expect(k8sClient.DeleteAllOf(ctx, &corev1.Node{})).To(Succeed())
		createNS(nsA)
		createNS(nsB)
		newIso()
		iso := waitCond("Ready", "PodCIDRUnknown")
		Expect(ownPolicies(iso)).To(BeEmpty())
		Expect(iso.Status.Summary).To(Equal("not enforced: pod ranges unknown"))

		stopMgr()
		stopMgr = startManager([]string{"10.99.0.0/16"})
		iso = waitCond("Ready", "Enforced")
		Expect(ownPolicies(iso)).To(HaveLen(2))
	})

	It("excludes the --pod-cidrs range and allows the --extra-allowed-cidrs, and is not Degraded", func() {
		stopMgr()
		stopMgr = startManagerExtra([]string{testClusterCIDR}, []string{"10.42.0.0/32"})
		createNS(nsA)
		createNS(nsB)
		createPod(nsA, "gw", map[string]string{appLabel: gatewayApp}, false)
		createPod(nsB, "dash", map[string]string{appLabel: dashboardApp}, false)
		newIso()
		iso := waitCond("Ready", "Enforced")
		Expect(meta.FindStatusCondition(iso.Status.Conditions, "Degraded").Reason).To(Equal("NoIssues"))
		p := &networkingv1.NetworkPolicy{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: nsB, Name: policyName(iso, "ingress", "dashboard")}, p)).To(Succeed())
		from := p.Spec.Ingress[0].From
		Expect(from[len(from)-2].IPBlock.Except).To(Equal([]string{testClusterCIDR}))
		Expect(from[len(from)-1].IPBlock.CIDR).To(Equal("10.42.0.0/32")) // the extra allowed address
	})

	It("keeps applying policies but is not Ready when a pod is outside the pod range", func() {
		stopMgr()
		stopMgr = startManager([]string{testClusterCIDR})
		createNS(nsA)
		createNS(nsB)
		createPod(nsA, "gw", map[string]string{appLabel: gatewayApp}, false)
		createPod(nsA, "gw-in", map[string]string{appLabel: gatewayApp}, false)
		createPod(nsB, "dash-host", map[string]string{appLabel: dashboardApp}, true)
		setPodIP(nsA, "gw", "10.1.2.3")
		setPodIP(nsA, "gw-in", "10.42.0.9")
		setPodIP(nsB, "dash-host", "172.16.0.1") // hostNetwork pods are skipped
		newIso()
		iso := waitCond("Ready", "PodRangeMismatch")
		Expect(ownPolicies(iso)).To(HaveLen(2)) // still enforced
		ready := meta.FindStatusCondition(iso.Status.Conditions, "Ready")
		Expect(ready.Message).To(ContainSubstring(nsA + "/gw (10.1.2.3)"))
		Expect(ready.Message).NotTo(ContainSubstring("gw-in"))
		Expect(ready.Message).NotTo(ContainSubstring("dash-host"))
		Expect(ready.Message).To(ContainSubstring("--pod-cidrs"))
		Expect(iso.Status.Summary).To(HaveSuffix("(1 pod outside the pod range)"))
		Expect(meta.FindStatusCondition(iso.Status.Conditions, "Degraded").Reason).To(Equal("HostNetworkPods"))
		hasEvent("PodRangeMismatch")
	})

	It("is Degraded, still Ready, when a node address is inside the pod range", func() {
		stopMgr()
		setNodeIP("node-1", "10.42.5.5")
		stopMgr = startManager([]string{testClusterCIDR})
		createNS(nsA)
		createNS(nsB)
		newIso()
		iso := waitCond("Ready", "Enforced")
		deg := waitCond("Degraded", "NodesInPodRange")
		Expect(meta.FindStatusCondition(deg.Status.Conditions, "Degraded").Message).To(ContainSubstring("node-1 (10.42.5.5)"))
		Expect(ownPolicies(iso)).To(HaveLen(2))
	})

	It("keeps existing policies and says so when an extra allowed CIDR would let pods in", func() {
		stopMgr()
		stopMgr = startManagerExtra([]string{testClusterCIDR}, []string{node1CIDR})
		createNS(nsA)
		createNS(nsB)
		newIso()
		iso := waitCond("Ready", "InvalidExtraAllowedCIDRs")
		Expect(iso.Status.Summary).To(Equal("not enforced: invalid extra allowed CIDRs"))
		Expect(ownPolicies(iso)).To(BeEmpty())

		// With policies already in place, the bad flag leaves them as they are.
		stopMgr()
		stopMgr = startManagerExtra([]string{testClusterCIDR}, []string{"10.42.0.0/32"})
		iso = waitCond("Ready", "Enforced")
		Expect(ownPolicies(iso)).To(HaveLen(2))
		stopMgr()
		stopMgr = startManagerExtra([]string{testClusterCIDR}, []string{node1CIDR})
		iso = waitCond("Ready", "InvalidExtraAllowedCIDRs")
		Expect(ownPolicies(iso)).To(HaveLen(2))
	})

	It("restores our policy when a tenant edits it", func() {
		createNS(nsA)
		createNS(nsB)
		newIso()
		iso := waitCond("Ready", "Enforced")
		key := types.NamespacedName{Namespace: nsB, Name: policyName(iso, "ingress", "dashboard")}
		want := &networkingv1.NetworkPolicy{}
		Expect(k8sClient.Get(ctx, key, want)).To(Succeed())

		// Tenant edit: narrow the selector two ways and add a rule that allows everything.
		Eventually(func() error {
			p := &networkingv1.NetworkPolicy{}
			if err := k8sClient.Get(ctx, key, p); err != nil {
				return err
			}
			p.Spec.PodSelector.MatchLabels["extra"] = "yes"
			p.Spec.PodSelector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "x", Operator: metav1.LabelSelectorOpExists}}
			p.Spec.Ingress = append(p.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{})
			return k8sClient.Update(ctx, p)
		}).Should(Succeed())

		Eventually(func(g Gomega) {
			got := &networkingv1.NetworkPolicy{}
			g.Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
			g.Expect(got.Spec).To(Equal(want.Spec))
		}).Should(Succeed())
	})

	It("still removes the old policy when applying the new one fails", func() {
		createNS(nsA)
		createNS(nsB)
		newIso()
		iso := waitCond("Ready", "Enforced")
		oldIngress := policyName(iso, "ingress", "dashboard")
		Expect(exists(nsB, oldIngress)()).To(Succeed())

		// envtest has no namespace controller, so a deleted namespace stays Terminating
		// and creating the egress policy in it fails.
		Expect(k8sClient.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsA}})).To(Succeed())
		Eventually(func() (corev1.NamespacePhase, error) {
			ns := &corev1.Namespace{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: nsA}, ns)
			return ns.Status.Phase, err
		}).Should(Equal(corev1.NamespaceTerminating))
		// A user policy makes the planner switch the gateway direction to an egress policy in nsA.
		createUserPolicy(nsB, "late", labelSel(appLabel, dashboardApp), networkingv1.PolicyTypeIngress)

		got := waitCond("Ready", "ApplyFailed")
		Expect(meta.FindStatusCondition(got.Status.Conditions, "Ready").Status).To(Equal(metav1.ConditionFalse))
		Expect(got.Status.Summary).To(Equal("not enforced: apply failed"))
		Eventually(exists(nsB, oldIngress)).Should(Satisfy(apierrors.IsNotFound))
		waitEvent(isoName, "ApplyFailed", corev1.EventTypeWarning)
	})

	It("keeps existing policies when pod ranges disappear, and recovers when they return", func() {
		createNS(nsA)
		createNS(nsB)
		newIso()
		iso := waitCond("Ready", "Enforced")
		Expect(ownPolicies(iso)).To(HaveLen(2))

		Expect(k8sClient.DeleteAllOf(ctx, &corev1.Node{})).To(Succeed())
		got := waitCond("Ready", "PodCIDRUnknown")
		Expect(meta.FindStatusCondition(got.Status.Conditions, "Ready").Status).To(Equal(metav1.ConditionFalse))
		Expect(ownPolicies(got)).To(HaveLen(2))

		createNode("node-2", "10.42.1.0/24")
		waitCond("Ready", "Enforced")
		Expect(ownPolicies(got)).To(HaveLen(2))
	})

	It("uses ingress when a user policy on the dashboard group is disjoint, egress when it overlaps", func() {
		createNS(nsA)
		createNS(nsB)
		createUserPolicy(nsB, "disjoint", labelSel(appLabel, "other"), networkingv1.PolicyTypeIngress)
		newIso()
		iso := waitCond("Ready", "Enforced")
		Expect(mechanisms(iso)[gatewayApp]).To(Equal(netsecv1alpha1.MechanismIngressPolicy))
	})

	It("uses egress on the gateway group when a user policy overlaps the dashboard group", func() {
		createNS(nsA)
		createNS(nsB)
		createUserPolicy(nsB, "overlaps", labelSel(appLabel, dashboardApp), networkingv1.PolicyTypeIngress)
		newIso()
		iso := waitCond("Ready", "Enforced")
		Expect(mechanisms(iso)).To(Equal(map[string]netsecv1alpha1.Mechanism{
			gatewayApp: netsecv1alpha1.MechanismEgressPolicy, dashboardApp: netsecv1alpha1.MechanismIngressPolicy,
		}))
		Expect(exists(nsA, policyName(iso, "egress", "gateway"))()).To(Succeed())
		Expect(exists(nsB, policyName(iso, "ingress", "dashboard"))()).NotTo(Succeed())
	})

	It("switches mechanism when a conflicting policy appears later", func() {
		createNS(nsA)
		createNS(nsB)
		newIso()
		iso := waitCond("Ready", "Enforced")
		Expect(exists(nsB, policyName(iso, "ingress", "dashboard"))()).To(Succeed())

		createUserPolicy(nsB, "late", labelSel(appLabel, dashboardApp), networkingv1.PolicyTypeIngress)
		Eventually(exists(nsA, policyName(iso, "egress", "gateway"))).Should(Succeed())
		Eventually(exists(nsB, policyName(iso, "ingress", "dashboard"))).Should(Satisfy(apierrors.IsNotFound))
		Eventually(func() (netsecv1alpha1.Mechanism, error) {
			err := k8sClient.Get(ctx, types.NamespacedName{Name: isoName}, iso)
			return mechanisms(iso)[gatewayApp], err
		}).Should(Equal(netsecv1alpha1.MechanismEgressPolicy))
		hasEvent("MechanismSwitched")
	})

	It("refuses a direction when both mechanisms are blocked, and removes our policies for it", func() {
		createNS(nsA)
		createNS(nsB)
		createUserPolicy(nsB, "blocks-ingress", labelSel(appLabel, dashboardApp), networkingv1.PolicyTypeIngress)
		createUserPolicy(nsA, "blocks-egress", labelSel(appLabel, gatewayApp), networkingv1.PolicyTypeEgress)
		newIso()
		iso := waitCond("Ready", "ConflictingPolicy")
		c := meta.FindStatusCondition(iso.Status.Conditions, "Ready")
		Expect(c.Status).To(Equal(metav1.ConditionFalse))
		Expect(c.Message).To(ContainSubstring(nsB + "/blocks-ingress"))
		Expect(c.Message).To(ContainSubstring(nsA + "/blocks-egress"))
		// Only dashboard -> gateway is left, as an ingress policy on the gateway group.
		// The refused direction stays in the list, with a plain message.
		Expect(mechanisms(iso)).To(Equal(map[string]netsecv1alpha1.Mechanism{"dashboard": netsecv1alpha1.MechanismIngressPolicy}))
		Expect(iso.Status.Traffic).To(HaveLen(2))
		Expect(iso.Status.Traffic[0].Blocked).To(BeFalse())
		Expect(iso.Status.Traffic[0].BlockedBy).To(BeEmpty())
		Expect(iso.Status.Traffic[0].Message).To(And(ContainSubstring(nsB+"/blocks-ingress"), ContainSubstring(nsA+"/blocks-egress"), ContainSubstring("cannot deny it")))
		Expect(iso.Status.Summary).To(Equal("dashboard → gateway blocked; gateway → dashboard NOT blocked (conflicting policy)"))
		Expect(exists(nsB, policyName(iso, "ingress", "dashboard"))()).NotTo(Succeed())
		Expect(exists(nsA, policyName(iso, "egress", "gateway"))()).NotTo(Succeed())
		Expect(ownPolicies(iso)).To(HaveLen(1))
		waitEvent(isoName, "IsolationRefused", corev1.EventTypeWarning)
	})

	It("restores our policy when someone edits or deletes it", func() {
		createNS(nsA)
		createNS(nsB)
		newIso()
		iso := waitCond("Ready", "Enforced")
		key := types.NamespacedName{Namespace: nsB, Name: policyName(iso, "ingress", "dashboard")}

		p := &networkingv1.NetworkPolicy{}
		Expect(k8sClient.Get(ctx, key, p)).To(Succeed())
		p.Spec.PodSelector = metav1.LabelSelector{}
		p.Spec.Ingress = nil
		Expect(k8sClient.Update(ctx, p)).To(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, key, p)).To(Succeed())
			g.Expect(p.Spec.PodSelector.MatchLabels).To(HaveKeyWithValue(appLabel, dashboardApp))
			g.Expect(p.Spec.Ingress).To(HaveLen(1))
		}).Should(Succeed())

		oldUID := p.UID
		Expect(k8sClient.Delete(ctx, p)).To(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, key, p)).To(Succeed())
			g.Expect(p.UID).NotTo(Equal(oldUID))
		}).Should(Succeed())
	})

	It("treats a forged label as a conflict and never deletes it", func() {
		createNS(nsA)
		createNS(nsB)
		newIso()
		iso := waitCond("Ready", "Enforced")

		forged := createUserPolicy(nsB, "forged", labelSel(appLabel, dashboardApp), networkingv1.PolicyTypeIngress)
		forged.Labels = map[string]string{uidLabel: string(iso.UID)}
		Expect(k8sClient.Update(ctx, forged)).To(Succeed())
		Eventually(exists(nsA, policyName(iso, "egress", "gateway"))).Should(Succeed())

		Expect(k8sClient.Delete(ctx, iso)).To(Succeed())
		Eventually(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Name: isoName}, &netsecv1alpha1.NetworkIsolation{})
		}).Should(Satisfy(apierrors.IsNotFound))
		Expect(exists(nsB, "forged")()).To(Succeed())
		Expect(exists(nsA, policyName(iso, "egress", "gateway"))()).NotTo(Succeed())
	})

	It("removes our policies when the isolation is deleted and leaves user policies alone", func() {
		createNS(nsA)
		createNS(nsB)
		user := createUserPolicy(nsA, "user", labelSel(appLabel, "other"), networkingv1.PolicyTypeIngress)
		newIso()
		iso := waitCond("Ready", "Enforced")
		Expect(ownPolicies(iso)).To(HaveLen(2))

		Expect(k8sClient.Delete(ctx, iso)).To(Succeed())
		Eventually(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Name: isoName}, &netsecv1alpha1.NetworkIsolation{})
		}).Should(Satisfy(apierrors.IsNotFound))
		Expect(ownPolicies(iso)).To(BeEmpty())
		after := &networkingv1.NetworkPolicy{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(user), after)).To(Succeed())
		Expect(after.ResourceVersion).To(Equal(user.ResourceVersion))
		hasEvent("PolicyRemoved")
	})

	It("refuses a selector with bad label syntax and reports it", func() {
		createNS(nsA)
		createNS(nsB)
		iso := &netsecv1alpha1.NetworkIsolation{
			ObjectMeta: metav1.ObjectMeta{Name: isoName},
			Spec: netsecv1alpha1.NetworkIsolationSpec{Between: []netsecv1alpha1.PodGroup{
				{Name: gatewayApp, Namespaces: []string{nsA}, PodSelector: labelSel(appLabel, gatewayApp)},
				{Name: dashboardApp, Namespaces: []string{nsB}, PodSelector: labelSel(appLabel, "a b")},
			}},
		}
		Expect(k8sClient.Create(ctx, iso)).To(Succeed())
		got := waitCond("Ready", "InvalidSelector")
		Expect(got.Status.Summary).To(Equal("not enforced: invalid selector in group dashboard"))
		Expect(meta.FindStatusCondition(got.Status.Conditions, "Ready").Message).To(ContainSubstring("group dashboard"))
		Expect(ownPolicies(got)).To(BeEmpty())
	})

	// editIso changes the live isolation's spec, retrying while the controller writes status.
	editIso := func(mutate func(*netsecv1alpha1.NetworkIsolation)) {
		Eventually(func(g Gomega) {
			cur := &netsecv1alpha1.NetworkIsolation{}
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: isoName}, cur)).To(Succeed())
			mutate(cur)
			g.Expect(k8sClient.Update(ctx, cur)).To(Succeed())
		}).Should(Succeed())
	}
	// policyUIDs maps each of our policies to its UID, to prove later that none was deleted and recreated.
	policyUIDs := func(iso *netsecv1alpha1.NetworkIsolation) map[string]types.UID {
		out := map[string]types.UID{}
		for _, p := range ownPolicies(iso) {
			out[p.Namespace+"/"+p.Name] = p.UID
		}
		return out
	}

	It("adds a policy in a namespace added to a live group, and never deletes the existing ones", func() {
		nsC := nsA + "-extra"
		createNS(nsA)
		createNS(nsB)
		createNS(nsC)
		newIso()
		iso := waitCond("Ready", "Enforced")
		before := policyUIDs(iso)
		Expect(before).To(HaveLen(2))

		editIso(func(cur *netsecv1alpha1.NetworkIsolation) {
			cur.Spec.Between[0].Namespaces = []string{nsA, nsC}
		})
		Eventually(exists(nsC, policyName(iso, "ingress", gatewayApp))).Should(Succeed())
		after := policyUIDs(waitCond("Ready", "Enforced"))
		Expect(after).To(HaveLen(3))
		for k, uid := range before {
			Expect(after).To(HaveKeyWithValue(k, uid), "existing policy %s was deleted or recreated", k)
		}
	})

	It("replaces policies when a group is renamed, leaving no leftovers", func() {
		createNS(nsA)
		createNS(nsB)
		newIso()
		iso := waitCond("Ready", "Enforced")
		oldName := policyName(iso, "ingress", dashboardApp)

		editIso(func(cur *netsecv1alpha1.NetworkIsolation) { cur.Spec.Between[1].Name = "console" })
		Eventually(exists(nsB, policyName(iso, "ingress", "console"))).Should(Succeed())
		Eventually(exists(nsB, oldName)).Should(Satisfy(apierrors.IsNotFound))
		got := waitCond("Ready", "Enforced")
		Expect(got.Status.Summary).To(Equal("gateway ⇄ console: blocked both ways (gateway, console match no pods)"))
		own := ownPolicies(got)
		names := make([]string, 0, len(own))
		for _, p := range own {
			names = append(names, p.Namespace+"/"+p.Name)
		}
		Expect(names).To(ConsistOf(
			nsB+"/"+policyName(iso, "ingress", "console"),
			nsA+"/"+policyName(iso, "ingress", gatewayApp),
		))
	})

	It("keeps the existing policies when an edit moves a group into a protected namespace", func() {
		createNS(nsA)
		createNS(nsB)
		createNS(protectedNS)
		newIso()
		iso := waitCond("Ready", "Enforced")
		before := policyUIDs(iso)

		editIso(func(cur *netsecv1alpha1.NetworkIsolation) {
			cur.Spec.Between[1].Namespaces = []string{protectedNS}
		})
		got := waitCond("Ready", "ProtectedNamespace")
		Expect(meta.FindStatusCondition(got.Status.Conditions, "Ready").Status).To(Equal(metav1.ConditionFalse))
		Expect(policyUIDs(got)).To(Equal(before))
		Expect(ownPolicies(got)).To(HaveLen(2))
	})

	It("refuses a namespace on the --protected-namespaces list", func() {
		createNS(nsA)
		createNS(protectedNS)
		iso := &netsecv1alpha1.NetworkIsolation{
			ObjectMeta: metav1.ObjectMeta{Name: isoName},
			Spec: netsecv1alpha1.NetworkIsolationSpec{
				Between: []netsecv1alpha1.PodGroup{
					{Name: gatewayApp, Namespaces: []string{nsA}},
					{Name: dashboardApp, Namespaces: []string{protectedNS}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, iso)).To(Succeed())
		got := waitCond("Ready", "ProtectedNamespace")
		Expect(meta.FindStatusCondition(got.Status.Conditions, "Ready").Message).To(ContainSubstring(protectedNS))
		Expect(ownPolicies(got)).To(BeEmpty())
	})

	It("reports a missing namespace and applies the policy once it exists", func() {
		createNS(nsA)
		newIso()
		iso := waitCond("Degraded", "NamespaceMissing")
		Expect(exists(nsA, policyName(iso, "ingress", "gateway"))()).To(Succeed())
		Expect(ownPolicies(iso)).To(HaveLen(1))

		createNS(nsB)
		Eventually(exists(nsB, policyName(iso, "ingress", "dashboard"))).Should(Succeed())
		waitCond("Ready", "Enforced")
	})

	It("lists hostNetwork pods and pods matching both groups in Degraded", func() {
		createNS(nsA)
		// Both groups live in one namespace; one pod carries both groups' labels.
		iso := &netsecv1alpha1.NetworkIsolation{
			ObjectMeta: metav1.ObjectMeta{Name: isoName},
			Spec: netsecv1alpha1.NetworkIsolationSpec{
				Between: []netsecv1alpha1.PodGroup{
					{Name: gatewayApp, Namespaces: []string{nsA}, PodSelector: labelSel(appLabel, gatewayApp)},
					{Name: dashboardApp, Namespaces: []string{nsA}, PodSelector: labelSel("tier", "web")},
				},
			},
		}
		createPod(nsA, "both", map[string]string{appLabel: gatewayApp, "tier": "web"}, true)
		Expect(k8sClient.Create(ctx, iso)).To(Succeed())

		got := waitCond("Degraded", "HostNetworkPods")
		c := meta.FindStatusCondition(got.Status.Conditions, "Degraded")
		Expect(c.Status).To(Equal(metav1.ConditionTrue))
		Expect(c.Message).To(ContainSubstring("hostNetwork pods cannot be isolated: " + nsA + "/both"))
		Expect(c.Message).To(ContainSubstring("pods match both groups: " + nsA + "/both"))
	})
})

const (
	testClusterCIDR = "10.42.0.0/16"
	node1CIDR       = "10.42.0.0/24" // the range of node-1
)

func labelSel(k, v string) metav1.LabelSelector {
	return metav1.LabelSelector{MatchLabels: map[string]string{k: v}}
}

func createNS(name string) {
	GinkgoHelper()
	err := k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
	Expect(client.IgnoreAlreadyExists(err)).To(Succeed())
}

func createNode(name string, cidrs ...string) {
	GinkgoHelper()
	Expect(k8sClient.Create(ctx, &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{PodCIDR: cidrs[0], PodCIDRs: cidrs},
	})).To(Succeed())
}

// setPodIP sets status.podIP and status.podIPs through the status subresource.
func setPodIP(ns, name, ip string) {
	GinkgoHelper()
	p := &corev1.Pod{}
	Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, p)).To(Succeed())
	p.Status.PodIP = ip
	p.Status.PodIPs = []corev1.PodIP{{IP: ip}}
	Expect(k8sClient.Status().Update(ctx, p)).To(Succeed())
}

// setNodeIP gives the node an InternalIP through the status subresource.
func setNodeIP(name, ip string) {
	GinkgoHelper()
	n := &corev1.Node{}
	Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name}, n)).To(Succeed())
	n.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}}
	Expect(k8sClient.Status().Update(ctx, n)).To(Succeed())
}

func createPod(ns, name string, labels map[string]string, hostNetwork bool) {
	GinkgoHelper()
	Expect(k8sClient.Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Spec: corev1.PodSpec{
			HostNetwork: hostNetwork,
			Containers:  []corev1.Container{{Name: "c", Image: "registry.k8s.io/pause:3.10"}},
		},
	})).To(Succeed())
}

// createUserPolicy makes a tenant's policy of one type that selects pods by label.
func createUserPolicy(ns, name string, sel metav1.LabelSelector, t networkingv1.PolicyType) *networkingv1.NetworkPolicy {
	GinkgoHelper()
	p := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       networkingv1.NetworkPolicySpec{PodSelector: sel, PolicyTypes: []networkingv1.PolicyType{t}},
	}
	Expect(k8sClient.Create(ctx, p)).To(Succeed())
	return p
}

// startManager runs the controller in its own manager, like cmd/main.go does.
// It returns a function that stops it and waits for it to finish.
func startManager(podCIDRs []string) func() {
	GinkgoHelper()
	return startManagerExtra(podCIDRs, nil)
}

// startManagerExtra is startManager with --extra-allowed-cidrs set.
func startManagerExtra(podCIDRs, extra []string) func() {
	GinkgoHelper()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:     scheme.Scheme,
		Metrics:    metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{SkipNameValidation: new(true)},
	})
	Expect(err).NotTo(HaveOccurred())
	Expect((&NetworkIsolationReconciler{
		Client:              mgr.GetClient(),
		APIReader:           mgr.GetAPIReader(),
		Scheme:              mgr.GetScheme(),
		Recorder:            mgr.GetEventRecorder("netsec-isolation-test"),
		ProtectedNamespaces: []string{protectedNS},
		PodCIDRs:            podCIDRs,
		ExtraAllowedCIDRs:   extra,
	}).SetupWithManager(mgr)).To(Succeed())

	mctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer GinkgoRecover()
		defer close(done)
		Expect(mgr.Start(mctx)).To(Succeed())
	}()
	return func() {
		stop()
		<-done
	}
}

// The CRD cannot check label syntax, so the controller must refuse a bad selector itself,
// keep what is already applied, and say which group is wrong.
func TestPlanRefusesInvalidSelector(t *testing.T) {
	iso := &netsecv1alpha1.NetworkIsolation{
		Status: netsecv1alpha1.NetworkIsolationStatus{Traffic: []netsecv1alpha1.Traffic{{From: "a", To: "b", Blocked: true}}},
		Spec: netsecv1alpha1.NetworkIsolationSpec{Between: []netsecv1alpha1.PodGroup{
			{Name: "a", Namespaces: []string{"x"}},
			{Name: "b", Namespaces: []string{"y"}, PodSelector: labelSel("app", "a b")},
		}},
	}
	res, err := (&NetworkIsolationReconciler{}).plan(context.Background(), iso)
	if err != nil {
		t.Fatal(err)
	}
	if !res.keep || !res.badSelector || len(res.desired) != 0 || len(res.traffic) != 1 {
		t.Errorf("want keep with no desired policies and the old traffic, got %+v", res)
	}
	if res.ready.Reason != "InvalidSelector" || !strings.Contains(res.ready.Message, "group b") {
		t.Errorf("ready = %+v, want InvalidSelector naming group b", res.ready)
	}
	if res.notEnforced != "invalid selector in group b" {
		t.Errorf("notEnforced = %q", res.notEnforced)
	}
}
