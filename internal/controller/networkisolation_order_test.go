package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	netsecv1alpha1 "github.com/nrndev/netsec/api/v1alpha1"
)

// Names shared by the fake-client specs in this package.
const (
	nsOne    = "ns-a"
	nsTwo    = "ns-b"
	testCIDR = "10.43.0.0/24"
	uidLabel = "netsec.nrnx.dev/isolation-uid"
)

// Editing a live isolation must never open a gap (US4.3): when a rename replaces a policy,
// every new policy is created before the old one is deleted. The envtest specs only see the
// end state, so this records the order of the calls.
func TestEditCreatesNewPoliciesBeforeDeletingOld(t *testing.T) {
	if err := netsecv1alpha1.AddToScheme(scheme.Scheme); err != nil {
		t.Fatal(err)
	}
	const oldPolicy = "netsec-3f2a9c1e-dashboard-ingress"
	iso := &netsecv1alpha1.NetworkIsolation{
		ObjectMeta: metav1.ObjectMeta{Name: "iso", UID: "3f2a9c1e-1111-2222-3333-444455556666", Finalizers: []string{isolationFinalizer}},
		Spec: netsecv1alpha1.NetworkIsolationSpec{Between: []netsecv1alpha1.PodGroup{
			{Name: gatewayApp, Namespaces: []string{nsOne}, PodSelector: labelSel(appLabel, gatewayApp)},
			// The group was called "dashboard" when the old policy was made.
			{Name: "console", Namespaces: []string{nsTwo}, PodSelector: labelSel(appLabel, dashboardApp)},
		}},
		Status: netsecv1alpha1.NetworkIsolationStatus{Traffic: []netsecv1alpha1.Traffic{
			{From: gatewayApp, To: dashboardApp, Blocked: true, Policies: []string{nsTwo + "/" + oldPolicy}},
		}},
	}
	old := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{
		Namespace: nsTwo, Name: oldPolicy, Labels: map[string]string{uidLabel: string(iso.UID)}}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n"}, Spec: corev1.NodeSpec{PodCIDR: testCIDR, PodCIDRs: []string{testCIDR}}}
	objs := []client.Object{iso, old, node,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsOne}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsTwo}}}

	var calls []string
	c := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(objs...).WithStatusSubresource(iso).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, o client.Object, opts ...client.CreateOption) error {
				if _, ok := o.(*networkingv1.NetworkPolicy); ok {
					calls = append(calls, "create "+o.GetNamespace()+"/"+o.GetName())
				}
				return cl.Create(ctx, o, opts...)
			},
			Delete: func(ctx context.Context, cl client.WithWatch, o client.Object, opts ...client.DeleteOption) error {
				if _, ok := o.(*networkingv1.NetworkPolicy); ok {
					calls = append(calls, "delete "+o.GetNamespace()+"/"+o.GetName())
				}
				return cl.Delete(ctx, o, opts...)
			},
		}).Build()
	r := &NetworkIsolationReconciler{Client: c, APIReader: c, Scheme: scheme.Scheme, Recorder: events.NewFakeRecorder(10)}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(iso)}); err != nil {
		t.Fatal(err)
	}

	// Two creates (the renamed group's policy and the other group's), then the one delete.
	if len(calls) != 3 || calls[2] != "delete "+nsTwo+"/"+oldPolicy {
		t.Errorf("calls = %v, want two creates and then the delete of %s", calls, oldPolicy)
	}
}
