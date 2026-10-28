package isolation

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/nrndev/netsec/api/v1alpha1"
)

const (
	keyApp     = "app"
	keyTier    = "tier"
	allV4      = "0.0.0.0/0"
	host0      = "10.42.0.0/32" // network address of cidr0, flannel's tunnel address on that node
	host1      = "10.42.1.0/32"
	hostV6     = "fd00::/128"
	podV6      = "fd00::/64"
	cidr0      = "10.42.0.0/24"
	clusterV4  = "10.42.0.0/16"
	anyV6      = "::/0"
	outside    = "192.168.0.0/16"
	nope       = "nope"
	cidr1      = "10.42.1.0/24"
	nsA        = "tenant-a"
	nsB        = "tenant-b"
	valDash    = "dashboard"
	valGateway = "gateway"
)

type pod struct {
	ns     string
	labels map[string]string
}

// peerMatches evaluates a peer that has a namespaceSelector against a pod.
func peerMatches(t *testing.T, p networkingv1.NetworkPolicyPeer, pd pod) bool {
	t.Helper()
	if p.NamespaceSelector == nil {
		t.Fatalf("peer has no namespaceSelector: %+v", p)
	}
	nsSel, err := metav1.LabelSelectorAsSelector(p.NamespaceSelector)
	if err != nil {
		t.Fatalf("namespaceSelector: %v", err)
	}
	if !nsSel.Matches(labels.Set{nsNameLabel: pd.ns}) {
		return false
	}
	if p.PodSelector == nil {
		return true
	}
	podSel, err := metav1.LabelSelectorAsSelector(p.PodSelector)
	if err != nil {
		t.Fatalf("podSelector: %v", err)
	}
	return podSel.Matches(labels.Set(pd.labels))
}

func req(k string, op metav1.LabelSelectorOperator, v ...string) metav1.LabelSelectorRequirement {
	return metav1.LabelSelectorRequirement{Key: k, Operator: op, Values: v}
}

func sel(l map[string]string, e ...metav1.LabelSelectorRequirement) metav1.LabelSelector {
	return metav1.LabelSelector{MatchLabels: l, MatchExpressions: e}
}

func allPods() []pod {
	out := make([]pod, 0, 48)
	for _, ns := range []string{"a1", "a2", "other", "a10"} {
		for _, app := range []string{"", "x", "y", "z"} {
			for _, tier := range []string{"", "f", "b"} {
				l := map[string]string{}
				if app != "" {
					l[keyApp] = app
				}
				if tier != "" {
					l[keyTier] = tier
				}
				out = append(out, pod{ns, l})
			}
		}
	}
	return out
}

func TestComplementIsExactlyTheOtherPods(t *testing.T) {
	ns := []string{"a1", "a2"}
	cases := map[string]metav1.LabelSelector{
		"empty":             {},
		"matchLabels":       sel(map[string]string{keyApp: "x"}),
		"two labels":        sel(map[string]string{keyApp: "x", keyTier: "f"}),
		"In":                sel(nil, req(keyApp, metav1.LabelSelectorOpIn, "x", "y")),
		"NotIn":             sel(nil, req(keyApp, metav1.LabelSelectorOpNotIn, "x")),
		"Exists":            sel(nil, req(keyTier, metav1.LabelSelectorOpExists)),
		"DoesNotExist":      sel(nil, req(keyApp, metav1.LabelSelectorOpDoesNotExist)),
		"labels and exprs":  sel(map[string]string{keyTier: "f"}, req(keyApp, metav1.LabelSelectorOpNotIn, "z")),
		"several exprs":     sel(nil, req(keyApp, metav1.LabelSelectorOpIn, "x", "y"), req(keyTier, metav1.LabelSelectorOpDoesNotExist)),
		"In and Exists mix": sel(nil, req(keyApp, metav1.LabelSelectorOpExists), req(keyTier, metav1.LabelSelectorOpIn, "b")),
	}
	for name, ps := range cases {
		t.Run(name, func(t *testing.T) {
			side := v1alpha1.PodGroup{Namespaces: ns, PodSelector: ps}
			peers, err := Complement(side)
			if err != nil {
				t.Fatal(err)
			}
			s, err := metav1.LabelSelectorAsSelector(&ps)
			if err != nil {
				t.Fatal(err)
			}
			for _, pd := range allPods() {
				inSide := slices.Contains(ns, pd.ns) && s.Matches(labels.Set(pd.labels))
				got := false
				for _, p := range peers {
					got = got || peerMatches(t, p, pd)
				}
				if got == inSide {
					t.Errorf("pod %s%v: complement matches=%v but inSide=%v", pd.ns, pd.labels, got, inSide)
				}
			}
		})
	}
}

func TestComplementEmptySelectorHasOnePeer(t *testing.T) {
	peers, err := Complement(v1alpha1.PodGroup{Namespaces: []string{"a"}})
	if err != nil || len(peers) != 1 {
		t.Fatalf("peers=%d err=%v; want 1 peer", len(peers), err)
	}
}

func TestComplementErrors(t *testing.T) {
	cases := map[string]v1alpha1.PodGroup{
		"unknown operator":  {Namespaces: []string{"a"}, PodSelector: sel(nil, req(keyApp, "Bogus", "x"))},
		"In without values": {Namespaces: []string{"a"}, PodSelector: sel(nil, req(keyApp, metav1.LabelSelectorOpIn))},
		"no namespaces":     {},
	}
	for name, side := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Complement(side); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestAllExcept(t *testing.T) {
	side := v1alpha1.PodGroup{Namespaces: []string{"a"}}
	cases := []struct {
		name    string
		cidrs   []string
		extra   []string
		want    []networkingv1.IPBlock
		wantErr bool
	}{
		{"v4 only, no automatic hosts", []string{cidr1, cidr0}, nil, []networkingv1.IPBlock{{CIDR: allV4, Except: []string{cidr0, cidr1}}}, false},
		{"dual stack", []string{cidr0, podV6}, nil, []networkingv1.IPBlock{{CIDR: allV4, Except: []string{cidr0}}, {CIDR: anyV6, Except: []string{podV6}}}, false},
		{"v6 only", []string{podV6}, nil, []networkingv1.IPBlock{{CIDR: anyV6, Except: []string{podV6}}}, false},
		{"duplicates collapse", []string{cidr0, cidr0}, nil, []networkingv1.IPBlock{{CIDR: allV4, Except: []string{cidr0}}}, false},
		{"host bits are masked", []string{"10.42.0.7/24"}, nil, []networkingv1.IPBlock{{CIDR: allV4, Except: []string{cidr0}}}, false},
		{"extras are appended, sorted, deduplicated", []string{cidr0, cidr1, podV6}, []string{host1, host0, host1, hostV6},
			[]networkingv1.IPBlock{{CIDR: allV4, Except: []string{cidr0, cidr1}}, {CIDR: anyV6, Except: []string{podV6}}, {CIDR: host0}, {CIDR: host1}, {CIDR: hostV6}}, false},
		{"extra outside the range may be wide", []string{cidr0}, []string{outside}, []networkingv1.IPBlock{{CIDR: allV4, Except: []string{cidr0}}, {CIDR: outside}}, false},
		{"invalid pod range", []string{cidr0, nope}, nil, nil, true},
		{"invalid extra", []string{cidr0}, []string{nope}, nil, true},
		{"wide extra inside the range", []string{cidr0}, []string{"10.42.0.0/25"}, nil, true},
		{"none", nil, nil, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			peers, err := AllExcept(side, c.cidrs, c.extra)
			if c.wantErr {
				if err == nil {
					t.Fatal("want an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []networkingv1.IPBlock
			for _, p := range peers[1:] { // peers[0] is the namespace peer
				got = append(got, *p.IPBlock)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("ipBlocks = %+v, want %+v", got, c.want)
			}
		})
	}
	if _, err := AllExcept(side, nil, nil); err != ErrNoPodCIDRs {
		t.Errorf("err = %v, want ErrNoPodCIDRs", err)
	}
}

func TestCheckExtraAllowed(t *testing.T) {
	cases := []struct {
		name    string
		extra   []string
		ranges  []string
		wantErr bool
	}{
		{"single host inside", []string{"10.42.0.0/32"}, []string{clusterV4}, false},
		{"single v6 host inside", []string{"fd00::/128"}, []string{podV6}, false},
		{"/24 inside", []string{"10.42.1.0/24"}, []string{clusterV4}, true},
		{"wider block containing the range", []string{"10.0.0.0/8"}, []string{clusterV4}, true},
		{"wide block outside", []string{outside}, []string{clusterV4}, false},
		{"wide v6 block does not touch a v4 range", []string{podV6}, []string{clusterV4}, false},
		{"one of several ranges", []string{"10.43.0.0/24"}, []string{clusterV4, "10.43.0.0/16"}, true},
		{"no extras", nil, []string{clusterV4}, false},
		{"invalid extra", []string{"10.42.0.1"}, []string{clusterV4}, true},
		{"invalid range", []string{"10.42.0.0/32"}, []string{nope}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := CheckExtraAllowed(c.extra, c.ranges); (err != nil) != c.wantErr {
				t.Errorf("err = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestRangeChecks(t *testing.T) {
	ranges := []string{clusterV4, podV6}
	objs := []Addrs{
		{"ns/in", []string{"10.42.1.5"}},
		{"ns/out", []string{"10.1.2.3"}},
		{"ns/mixed", []string{"10.42.1.6", "fd01::1"}}, // dual stack, v6 outside a v6 range
		{"ns/dual-in", []string{"10.42.1.7", "fd00::7"}},
		{"ns/mapped", []string{"::ffff:10.42.1.8"}},
		{"ns/none", nil},
		{"ns/junk", []string{nope}},
	}
	out, err := OutsideRange(objs, ranges)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ns/out (10.1.2.3)", "ns/mixed (fd01::1)", "ns/junk (nope)"}; !reflect.DeepEqual(out, want) {
		t.Errorf("OutsideRange = %v, want %v", out, want)
	}
	in, err := InRange(objs, ranges, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ns/in (10.42.1.5)", "ns/mixed (10.42.1.6)", "ns/dual-in (10.42.1.7, fd00::7)", "ns/mapped (::ffff:10.42.1.8)"}; !reflect.DeepEqual(in, want) {
		t.Errorf("InRange = %v, want %v", in, want)
	}
	if _, err := OutsideRange(objs, []string{nope}); err == nil {
		t.Error("want an error for a bad range")
	}
}

// A family with no pod range has no ipBlock, so its pod IPs cannot leak: not a mismatch.
func TestOutsideRangeIgnoresFamilyWithoutRange(t *testing.T) {
	pods := []Addrs{{"ns/v6", []string{"fd01::1"}}, {"ns/v4", []string{"10.1.2.3"}}, {"ns/v4in", []string{"10.42.1.1"}}}
	out, err := OutsideRange(pods, []string{clusterV4})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ns/v4 (10.1.2.3)"}; !reflect.DeepEqual(out, want) {
		t.Errorf("v4 range only: %v, want %v", out, want)
	}
	out, _ = OutsideRange(pods, []string{podV6})
	if want := []string{"ns/v6 (fd01::1)"}; !reflect.DeepEqual(out, want) {
		t.Errorf("v6 range only: %v, want %v", out, want)
	}
}

// A node IP covered by an extra allowed address is already allowed: not reported.
func TestInRangeSkipsCovered(t *testing.T) {
	nodes := []Addrs{{"covered", []string{"10.42.0.7"}}, {"uncovered", []string{"10.42.0.8"}}, {"outside", []string{"172.20.0.3"}}}
	out, err := InRange(nodes, []string{clusterV4}, []string{"10.42.0.7/32"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"uncovered (10.42.0.8)"}; !reflect.DeepEqual(out, want) {
		t.Errorf("InRange = %v, want %v", out, want)
	}
	if _, err := InRange(nodes, []string{clusterV4}, []string{nope}); err == nil {
		t.Error("want an error for a bad covered CIDR")
	}
}

func TestWithMismatch(t *testing.T) {
	for n, want := range map[int]string{0: "s", 1: "s (1 pod outside the pod range)", 3: "s (3 pods outside the pod range)"} {
		if got := WithMismatch("s", n); got != want {
			t.Errorf("WithMismatch(%d) = %q, want %q", n, got, want)
		}
	}
}

// The host blocks must never let a pod in: no pod IP in a range may match any peer ipBlock
// except through the except list, and Complement must be unchanged.
func TestAllExceptKeepsPodsOut(t *testing.T) {
	side := v1alpha1.PodGroup{Namespaces: []string{"a"}}
	peers, err := AllExcept(side, []string{cidr0, cidr1}, []string{host0, host1})
	if err != nil {
		t.Fatal(err)
	}
	comp, _ := Complement(side)
	if !reflect.DeepEqual(peers[:len(comp)], comp) {
		t.Errorf("leading peers = %+v, want Complement %+v", peers[:len(comp)], comp)
	}
	for _, c := range []string{cidr0, cidr1} {
		pfx := netip.MustParsePrefix(c)
		for i, ip := 1, pfx.Addr().Next(); pfx.Contains(ip) && i < 300; i, ip = i+1, ip.Next() {
			if allowedByIPBlocks(peers[len(comp):], ip) {
				t.Fatalf("pod IP %s in %s is allowed", ip, c)
			}
		}
		if !allowedByIPBlocks(peers[len(comp):], pfx.Addr()) {
			t.Errorf("tunnel address %s is not allowed", pfx.Addr())
		}
	}
}

// The pod range is the cluster-wide one: an IP in it that is not an extra is excluded,
// and an extra single address inside it is let in.
func TestAllExceptClusterRange(t *testing.T) {
	side := v1alpha1.PodGroup{Namespaces: []string{"a"}}
	cluster := []string{"10.42.0.0/16"}
	peers, err := AllExcept(side, cluster, []string{host0})
	if err != nil {
		t.Fatal(err)
	}
	comp, _ := Complement(side)
	blocks := peers[len(comp):]
	if allowedByIPBlocks(blocks, netip.MustParseAddr("10.42.77.5")) {
		t.Error("a pod IP in the cluster range is allowed")
	}
	if !allowedByIPBlocks(blocks, netip.MustParseAddr("10.42.0.0")) {
		t.Error("the extra address is not allowed")
	}
	if allowedByIPBlocks(blocks, netip.MustParseAddr("10.42.1.0")) {
		t.Error("10.42.1.0 is not an extra, so it must not be allowed")
	}
}

func allowedByIPBlocks(peers []networkingv1.NetworkPolicyPeer, ip netip.Addr) bool {
	for _, p := range peers {
		b := p.IPBlock
		if !netip.MustParsePrefix(b.CIDR).Contains(ip) {
			continue
		}
		excepted := false
		for _, e := range b.Except {
			excepted = excepted || netip.MustParsePrefix(e).Contains(ip)
		}
		if !excepted {
			return true
		}
	}
	return false
}

func TestMayOverlap(t *testing.T) {
	cases := []struct {
		name string
		a, b metav1.LabelSelector
		want bool
	}{
		{"both empty", sel(nil), sel(nil), true},
		{"one empty", sel(map[string]string{keyApp: "x"}), sel(nil), true},
		{"same value", sel(map[string]string{keyApp: "x"}), sel(map[string]string{keyApp: "x"}), true},
		{"different values", sel(map[string]string{keyApp: "x"}), sel(map[string]string{keyApp: "y"}), false},
		{"different keys", sel(map[string]string{keyApp: "x"}), sel(map[string]string{keyTier: "y"}), true},
		{"In sets share a value", sel(nil, req(keyApp, metav1.LabelSelectorOpIn, "x", "y")), sel(nil, req(keyApp, metav1.LabelSelectorOpIn, "y", "z")), true},
		{"In sets are disjoint", sel(nil, req(keyApp, metav1.LabelSelectorOpIn, "x")), sel(nil, req(keyApp, metav1.LabelSelectorOpIn, "y", "z")), false},
		{"Exists vs DoesNotExist", sel(nil, req(keyApp, metav1.LabelSelectorOpExists)), sel(nil, req(keyApp, metav1.LabelSelectorOpDoesNotExist)), false},
		{"In vs NotIn same value", sel(nil, req(keyApp, metav1.LabelSelectorOpIn, "x")), sel(nil, req(keyApp, metav1.LabelSelectorOpNotIn, "x")), false},
		{"In vs NotIn other value", sel(nil, req(keyApp, metav1.LabelSelectorOpIn, "x")), sel(nil, req(keyApp, metav1.LabelSelectorOpNotIn, "y")), true},
		{"In covered by NotIn", sel(nil, req(keyApp, metav1.LabelSelectorOpIn, "x", "y")), sel(nil, req(keyApp, metav1.LabelSelectorOpNotIn, "x", "y")), false},
		{"matchLabels vs DoesNotExist", sel(map[string]string{keyApp: "x"}), sel(nil, req(keyApp, metav1.LabelSelectorOpDoesNotExist)), false},
		{"NotIn vs DoesNotExist", sel(nil, req(keyApp, metav1.LabelSelectorOpNotIn, "x")), sel(nil, req(keyApp, metav1.LabelSelectorOpDoesNotExist)), true},
		{"NotIn vs Exists", sel(nil, req(keyApp, metav1.LabelSelectorOpNotIn, "x")), sel(nil, req(keyApp, metav1.LabelSelectorOpExists)), true},
		{"one key clashes, others fine", sel(map[string]string{keyApp: "x", keyTier: "f"}), sel(map[string]string{keyApp: "x", keyTier: "b"}), false},
		{"unknown operator is ignored", sel(nil, req(keyApp, "Bogus", "x")), sel(map[string]string{keyApp: "y"}), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MayOverlap(&c.a, &c.b); got != c.want {
				t.Errorf("MayOverlap = %v, want %v", got, c.want)
			}
			if got := MayOverlap(&c.b, &c.a); got != c.want {
				t.Errorf("MayOverlap (swapped) = %v, want %v", got, c.want)
			}
		})
	}
}

// MayOverlap must never say "no overlap" when a pod matches both selectors.
func TestMayOverlapNeverMissesARealOverlap(t *testing.T) {
	sels := []metav1.LabelSelector{
		{},
		sel(map[string]string{keyApp: "x"}),
		sel(map[string]string{keyApp: "y", keyTier: "f"}),
		sel(nil, req(keyApp, metav1.LabelSelectorOpIn, "x", "y")),
		sel(nil, req(keyApp, metav1.LabelSelectorOpNotIn, "x")),
		sel(nil, req(keyApp, metav1.LabelSelectorOpExists)),
		sel(nil, req(keyApp, metav1.LabelSelectorOpDoesNotExist)),
		sel(nil, req(keyTier, metav1.LabelSelectorOpExists), req(keyApp, metav1.LabelSelectorOpNotIn, "z")),
	}
	for i, a := range sels {
		for j, b := range sels {
			sa, _ := metav1.LabelSelectorAsSelector(&a)
			sb, _ := metav1.LabelSelectorAsSelector(&b)
			real := false
			for _, pd := range allPods() {
				real = real || (sa.Matches(labels.Set(pd.labels)) && sb.Matches(labels.Set(pd.labels)))
			}
			if got := MayOverlap(&a, &b); real && !got {
				t.Errorf("selectors %d,%d share a pod but MayOverlap=false", i, j)
			}
			// The pod universe above covers every label case, so the answer is exact here.
			if got := MayOverlap(&a, &b); got != real {
				t.Errorf("selectors %d,%d: MayOverlap=%v, real=%v", i, j, got, real)
			}
		}
	}
}

func testIso() *v1alpha1.NetworkIsolation {
	return &v1alpha1.NetworkIsolation{
		ObjectMeta: metav1.ObjectMeta{Name: "contain-gateway-dashboard", UID: types.UID("3f2a9c1e-1111-2222-3333-444455556666")},
		Spec: v1alpha1.NetworkIsolationSpec{
			Between: []v1alpha1.PodGroup{
				{Name: valGateway, Namespaces: []string{nsA}, PodSelector: sel(map[string]string{keyApp: valGateway})},
				{Name: "dashboard", Namespaces: []string{nsB}, PodSelector: sel(map[string]string{keyApp: valDash})},
			},
		},
	}
}

// The policy checked against the example in design §3.1.
func TestPoliciesIngressMatchesDesignExample(t *testing.T) {
	iso := testIso()
	got, err := Policies(iso, "gateway", v1alpha1.MechanismIngressPolicy, []string{cidr0, cidr1}, []string{host0, host1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d policies, want 1", len(got))
	}
	p := got[0]
	if p.Name != "netsec-3f2a9c1e-dashboard-ingress" || p.Namespace != nsB {
		t.Errorf("name/namespace = %s/%s", p.Namespace, p.Name)
	}
	wantLabels := map[string]string{LabelManagedBy: "netsec", LabelIsolationUID: string(iso.UID)}
	if !reflect.DeepEqual(p.Labels, wantLabels) {
		t.Errorf("labels = %v", p.Labels)
	}
	if !reflect.DeepEqual(p.Annotations, map[string]string{AnnotationIsolation: "contain-gateway-dashboard"}) {
		t.Errorf("annotations = %v", p.Annotations)
	}
	if len(p.OwnerReferences) != 1 {
		t.Fatalf("ownerReferences = %v", p.OwnerReferences)
	}
	o := p.OwnerReferences[0]
	if o.Kind != "NetworkIsolation" || o.APIVersion != "netsec.nrnx.dev/v1alpha1" || o.Name != iso.Name || o.UID != iso.UID || o.Controller == nil || !*o.Controller {
		t.Errorf("ownerReference = %+v", o)
	}
	if !reflect.DeepEqual(p.Spec.PodSelector, sel(map[string]string{keyApp: valDash})) {
		t.Errorf("podSelector = %+v", p.Spec.PodSelector)
	}
	if !reflect.DeepEqual(p.Spec.PolicyTypes, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}) || len(p.Spec.Egress) != 0 {
		t.Errorf("policyTypes = %v, egress = %v", p.Spec.PolicyTypes, p.Spec.Egress)
	}
	wantFrom := []networkingv1.NetworkPolicyPeer{
		{NamespaceSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{req(nsNameLabel, metav1.LabelSelectorOpNotIn, nsA)}}},
		{
			NamespaceSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{req(nsNameLabel, metav1.LabelSelectorOpIn, nsA)}},
			PodSelector:       &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{req(keyApp, metav1.LabelSelectorOpNotIn, "gateway")}},
		},
		{IPBlock: &networkingv1.IPBlock{CIDR: allV4, Except: []string{cidr0, cidr1}}},
		{IPBlock: &networkingv1.IPBlock{CIDR: host0}},
		{IPBlock: &networkingv1.IPBlock{CIDR: host1}},
	}
	if len(p.Spec.Ingress) != 1 || !reflect.DeepEqual(p.Spec.Ingress[0].From, wantFrom) {
		t.Errorf("ingress = %+v", p.Spec.Ingress)
	}
}

func TestPoliciesEgressAndNamespaces(t *testing.T) {
	iso := testIso()
	iso.Spec.Between[0].Namespaces = []string{nsA, "tenant-a2"}
	got, err := Policies(iso, "gateway", v1alpha1.MechanismEgressPolicy, []string{cidr0}, []string{host0})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Namespace != nsA || got[1].Namespace != "tenant-a2" {
		t.Fatalf("policies = %+v", got)
	}
	p := got[1]
	if p.Name != "netsec-3f2a9c1e-gateway-egress" {
		t.Errorf("name = %s", p.Name)
	}
	if !reflect.DeepEqual(p.Spec.PolicyTypes, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}) || len(p.Spec.Ingress) != 0 || len(p.Spec.Egress) != 1 {
		t.Errorf("spec = %+v", p.Spec)
	}
	// The egress policy must exclude the dashboard group, not the gateway group.
	if ns := p.Spec.Egress[0].To[0].NamespaceSelector.MatchExpressions[0].Values; !reflect.DeepEqual(ns, []string{nsB}) {
		t.Errorf("egress excludes %v, want tenant-b", ns)
	}
}

func TestPoliciesErrors(t *testing.T) {
	short := testIso()
	short.UID = "abc"
	cases := map[string]struct {
		iso   *v1alpha1.NetworkIsolation
		mech  v1alpha1.Mechanism
		cidrs []string
	}{
		"short uid":     {short, v1alpha1.MechanismIngressPolicy, []string{"10.0.0.0/24"}},
		"no cidrs":      {testIso(), v1alpha1.MechanismIngressPolicy, nil},
		"bad mechanism": {testIso(), Refused, []string{"10.0.0.0/24"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Policies(c.iso, "gateway", c.mech, c.cidrs, nil); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func userPolicy(ns, name string, pts []networkingv1.PolicyType, selector metav1.LabelSelector) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       networkingv1.NetworkPolicySpec{PodSelector: selector, PolicyTypes: pts},
	}
}

var (
	ingressT = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	egressT  = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
)

func TestPlanDirection(t *testing.T) {
	const uid = "3f2a9c1e-1111-2222-3333-444455556666"
	iso := testIso()
	from, to := iso.Spec.Between[0], iso.Spec.Between[1] // gateway -> dashboard: ingress on tenant-b, egress on tenant-a

	userIn := userPolicy(nsB, "allow-dash", ingressT, sel(map[string]string{keyApp: valDash}))
	userEg := userPolicy(nsA, "gw-egress", egressT, sel(map[string]string{keyApp: "gateway"}))
	disjointIn := userPolicy(nsB, "other-app", ingressT, sel(map[string]string{keyApp: "db"}))
	otherIsoIn := userPolicy(nsB, "netsec-deadbeef-dashboard-ingress", ingressT, sel(map[string]string{keyApp: valDash}))
	otherIsoIn.Labels = map[string]string{LabelIsolationUID: "deadbeef-other"}
	ownIn := userPolicy(nsB, "netsec-3f2a9c1e-dashboard-ingress", ingressT, sel(map[string]string{keyApp: valDash}))
	ownIn.Labels = map[string]string{LabelIsolationUID: uid}
	spoofed := userPolicy(nsB, "tenant-allow-a", ingressT, sel(map[string]string{keyApp: valDash}))
	spoofed.Labels = map[string]string{LabelIsolationUID: uid}
	wrongNsIn := userPolicy("elsewhere", "x", ingressT, sel(nil))
	egressOnTargetNs := userPolicy(nsB, "dash-egress", egressT, sel(nil)) // egress in B's ns: irrelevant to A->B
	noTypesIn := userPolicy(nsB, "legacy", nil, sel(nil))                 // empty policyTypes means Ingress

	cases := []struct {
		name     string
		policies []networkingv1.NetworkPolicy
		current  v1alpha1.Mechanism
		want     v1alpha1.Mechanism
		conflict []string
	}{
		{"free target gives ingress", nil, "", v1alpha1.MechanismIngressPolicy, nil},
		{"overlapping user ingress falls to egress", []networkingv1.NetworkPolicy{userIn}, "", v1alpha1.MechanismEgressPolicy, nil},
		{"disjoint user policy does not block", []networkingv1.NetworkPolicy{disjointIn}, "", v1alpha1.MechanismIngressPolicy, nil},
		{"another isolation's policy counts", []networkingv1.NetworkPolicy{otherIsoIn}, "", v1alpha1.MechanismEgressPolicy, nil},
		{"our label on a policy with another name still counts", []networkingv1.NetworkPolicy{spoofed}, "", v1alpha1.MechanismEgressPolicy, nil},
		{"our own policy is ignored", []networkingv1.NetworkPolicy{ownIn}, "", v1alpha1.MechanismIngressPolicy, nil},
		{"policy outside the group's namespaces is ignored", []networkingv1.NetworkPolicy{wrongNsIn}, "", v1alpha1.MechanismIngressPolicy, nil},
		{"egress policy on the target does not block ingress", []networkingv1.NetworkPolicy{egressOnTargetNs}, "", v1alpha1.MechanismIngressPolicy, nil},
		{"empty policyTypes counts as ingress", []networkingv1.NetworkPolicy{noTypesIn}, "", v1alpha1.MechanismEgressPolicy, nil},
		{"sticky egress is kept while valid", nil, v1alpha1.MechanismEgressPolicy, v1alpha1.MechanismEgressPolicy, nil},
		{"sticky egress is dropped when invalid", []networkingv1.NetworkPolicy{userEg}, v1alpha1.MechanismEgressPolicy, v1alpha1.MechanismIngressPolicy, nil},
		{"sticky ingress is dropped when invalid", []networkingv1.NetworkPolicy{userIn}, v1alpha1.MechanismIngressPolicy, v1alpha1.MechanismEgressPolicy, nil},
		{"sticky ingress is kept while valid", []networkingv1.NetworkPolicy{userEg}, v1alpha1.MechanismIngressPolicy, v1alpha1.MechanismIngressPolicy, nil},
		{"refused lists the conflicts", []networkingv1.NetworkPolicy{userIn, userEg, disjointIn}, "", Refused, []string{"tenant-a/gw-egress", "tenant-b/allow-dash"}},
		{"refused even when sticky", []networkingv1.NetworkPolicy{userIn, userEg}, v1alpha1.MechanismEgressPolicy, Refused, []string{"tenant-a/gw-egress", "tenant-b/allow-dash"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := PlanDirection(iso, from, to, c.policies, c.current)
			if got.Mechanism != c.want {
				t.Errorf("mechanism = %q, want %q", got.Mechanism, c.want)
			}
			if !reflect.DeepEqual(got.Conflicts, c.conflict) {
				t.Errorf("conflicts = %v, want %v", got.Conflicts, c.conflict)
			}
		})
	}
}

// Both directions are planned separately: B -> A looks at ingress on A and egress on B.
func TestPlanDirectionReverse(t *testing.T) {
	iso := testIso()
	userInA := userPolicy(nsA, "gw-in", ingressT, sel(nil))
	got := PlanDirection(iso, iso.Spec.Between[1], iso.Spec.Between[0], []networkingv1.NetworkPolicy{userInA}, "")
	if got.Mechanism != v1alpha1.MechanismEgressPolicy {
		t.Errorf("dashboard->gateway mechanism = %q, want EgressPolicy", got.Mechanism)
	}
	fwd := PlanDirection(iso, iso.Spec.Between[0], iso.Spec.Between[1], []networkingv1.NetworkPolicy{userInA}, "")
	if fwd.Mechanism != v1alpha1.MechanismIngressPolicy {
		t.Errorf("gateway->dashboard mechanism = %q, want IngressPolicy", fwd.Mechanism)
	}
}

func TestIsOwn(t *testing.T) {
	iso := testIso()
	uid := string(iso.UID)
	mk := func(name, label string) networkingv1.NetworkPolicy {
		return networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: nsB, Labels: map[string]string{LabelIsolationUID: label}}}
	}
	for n, ns := range map[string]string{"gateway-ingress": nsA, "dashboard-ingress": nsB, "gateway-egress": nsA, "dashboard-egress": nsB} {
		p := mk("netsec-3f2a9c1e-"+n, uid)
		p.Namespace = ns
		if !IsOwn(p, iso) {
			t.Errorf("%s should be ours", n)
		}
	}
	// A generated name in a namespace outside that group is not ours.
	wrongNS := mk("netsec-3f2a9c1e-gateway-ingress", uid) // gateway's namespace is nsA, not nsB
	if IsOwn(wrongNS, iso) {
		t.Error("a generated name in another group's namespace should not be ours")
	}
	wrongNS.Namespace = "elsewhere"
	if IsOwn(wrongNS, iso) {
		t.Error("a generated name outside every group namespace should not be ours")
	}
	for name, p := range map[string]networkingv1.NetworkPolicy{
		"label, other name":    mk("allow-dashboard", uid),
		"label, other group":   mk("netsec-3f2a9c1e-other-ingress", uid),
		"name, other label":    mk("netsec-3f2a9c1e-dashboard-ingress", "other"),
		"name, no label":       {ObjectMeta: metav1.ObjectMeta{Name: "netsec-3f2a9c1e-dashboard-ingress", Namespace: nsB}},
		"another uid's prefix": mk("netsec-deadbeef-dashboard-ingress", uid),
	} {
		if IsOwn(p, iso) {
			t.Errorf("%s should not be ours", name)
		}
	}
	// A policy from before an edit counts only when status lists it, in its own namespace.
	old := mk("netsec-3f2a9c1e-oldname-ingress", uid)
	old.Namespace = "ns-a"
	if IsOwn(old, iso) {
		t.Error("an unlisted old name should not be ours")
	}
	iso.Status.Traffic = []v1alpha1.Traffic{{From: "oldname", To: valDash, Blocked: true, Policies: []string{"ns-a/netsec-3f2a9c1e-oldname-ingress"}}}
	if !IsOwn(old, iso) {
		t.Error("a policy listed in status should be ours")
	}
	old.Namespace = "ns-b"
	if IsOwn(old, iso) {
		t.Error("status lists namespace/name: the same name in another namespace is not ours")
	}
	forged := mk("netsec-3f2a9c1e-oldname-ingress", "other")
	forged.Namespace = "ns-a"
	if IsOwn(forged, iso) {
		t.Error("a listed name with another uid's label is not ours")
	}
	short := testIso()
	short.UID = "short"
	if IsOwn(mk("x", "short"), short) {
		t.Error("short uid must never match")
	}
}

func TestSummary(t *testing.T) {
	tr := func(from, to string, blocked bool) v1alpha1.Traffic {
		return v1alpha1.Traffic{From: from, To: to, Blocked: blocked}
	}
	both := []v1alpha1.Traffic{tr(valGateway, valDash, true), tr(valDash, valGateway, true)}
	cases := []struct {
		name        string
		traffic     []v1alpha1.Traffic
		pods        []v1alpha1.GroupPods
		notEnforced string
		want        string
	}{
		{"both blocked", []v1alpha1.Traffic{tr("gateway", "dashboard", true), tr("dashboard", "gateway", true)}, nil, "", "gateway ⇄ dashboard: blocked both ways"},
		{"one refused", []v1alpha1.Traffic{tr("gateway", "dashboard", true), tr("dashboard", "gateway", false)}, nil, "", "gateway → dashboard blocked; dashboard → gateway NOT blocked (conflicting policy)"},
		{"other one refused", []v1alpha1.Traffic{tr("gateway", "dashboard", false), tr("dashboard", "gateway", true)}, nil, "", "dashboard → gateway blocked; gateway → dashboard NOT blocked (conflicting policy)"},
		{"both refused", []v1alpha1.Traffic{tr("gateway", "dashboard", false), tr("dashboard", "gateway", false)}, nil, "", "gateway ⇄ dashboard: NOT blocked (conflicting policy)"},
		{"edit not applied, both still blocked", []v1alpha1.Traffic{tr("gateway", "dashboard", true), tr("dashboard", "gateway", true)}, nil, "pod ranges unknown", "gateway ⇄ dashboard: blocked both ways (edit not applied: pod ranges unknown)"},
		{"edit not applied, one still blocked", []v1alpha1.Traffic{tr("gateway", "dashboard", true), tr("dashboard", "gateway", false)}, nil, "protected namespace", "gateway → dashboard blocked; dashboard → gateway NOT blocked (conflicting policy) (edit not applied: protected namespace)"},
		{"nothing blocked before", []v1alpha1.Traffic{tr("gateway", "dashboard", false), tr("dashboard", "gateway", false)}, nil, "pod ranges unknown", "not enforced: pod ranges unknown"},
		{"no traffic before", nil, nil, "invalid selector in group a", "not enforced: invalid selector in group a"},
		{"one group empty", both, []v1alpha1.GroupPods{{Group: valGateway, Count: 2}, {Group: valDash, Count: 0}}, "", "gateway ⇄ dashboard: blocked both ways (dashboard matches no pods)"},
		{"both groups empty", both, []v1alpha1.GroupPods{{Group: valGateway, Count: 0}, {Group: valDash, Count: 0}}, "", "gateway ⇄ dashboard: blocked both ways (gateway, dashboard match no pods)"},
		{"both groups have pods", both, []v1alpha1.GroupPods{{Group: valGateway, Count: 1}, {Group: valDash, Count: 1}}, "", "gateway ⇄ dashboard: blocked both ways"},
		{"no traffic", nil, nil, "", "not enforced: no traffic planned yet"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Summary(c.traffic, c.pods, c.notEnforced); got != c.want {
				t.Errorf("summary = %q, want %q", got, c.want)
			}
		})
	}
}
