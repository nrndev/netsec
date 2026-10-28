package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	netsecv1alpha1 "github.com/nrndev/netsec/api/v1alpha1"
)

// A conflict while updating our policy is a harmless race. The pass must retry soon and
// leave status alone and emit nothing; any other apply error still reports ApplyFailed.
func TestApplyConflictIsRetriedQuietly(t *testing.T) {
	for name, tc := range map[string]struct {
		err         error
		wantRequeue time.Duration
		wantFailed  bool
	}{
		"conflict":  {apierrors.NewConflict(schema.GroupResource{Group: "networking.k8s.io", Resource: "networkpolicies"}, "p", nil), time.Second, false},
		"forbidden": {apierrors.NewForbidden(schema.GroupResource{Resource: "networkpolicies"}, "p", nil), 0, true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := netsecv1alpha1.AddToScheme(scheme.Scheme); err != nil {
				t.Fatal(err)
			}
			iso := &netsecv1alpha1.NetworkIsolation{
				ObjectMeta: metav1.ObjectMeta{Name: "iso", UID: "3f2a9c1e-1111-2222-3333-444455556666", Finalizers: []string{isolationFinalizer}},
				Spec: netsecv1alpha1.NetworkIsolationSpec{Between: []netsecv1alpha1.PodGroup{
					{Name: "a", Namespaces: []string{nsOne}, PodSelector: labelSel("app", "a")},
					{Name: "b", Namespaces: []string{nsTwo}, PodSelector: labelSel("app", "b")},
				}},
			}
			iso.Status.Conditions = []metav1.Condition{{Type: condReady, Status: metav1.ConditionTrue, Reason: "Enforced"}}
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n"}, Spec: corev1.NodeSpec{PodCIDR: testCIDR, PodCIDRs: []string{testCIDR}}}
			objs := []client.Object{iso, node,
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsOne}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsTwo}}}
			c := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(objs...).WithStatusSubresource(iso).
				WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, cl client.WithWatch, o client.Object, opts ...client.CreateOption) error {
					if _, ok := o.(*networkingv1.NetworkPolicy); ok {
						return tc.err
					}
					return cl.Create(ctx, o, opts...)
				}}).Build()
			rec := events.NewFakeRecorder(10)
			r := &NetworkIsolationReconciler{Client: c, APIReader: c, Scheme: scheme.Scheme, Recorder: rec}

			res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(iso)})
			got := &netsecv1alpha1.NetworkIsolation{}
			if gerr := c.Get(context.Background(), client.ObjectKeyFromObject(iso), got); gerr != nil {
				t.Fatal(gerr)
			}
			ready := ""
			for _, cd := range got.Status.Conditions {
				if cd.Type == condReady {
					ready = cd.Reason
				}
			}
			if tc.wantFailed {
				if err == nil || ready != "ApplyFailed" || len(rec.Events) == 0 {
					t.Errorf("err=%v ready=%q events=%d, want an error, ApplyFailed and an event", err, ready, len(rec.Events))
				}
				return
			}
			if err != nil || res.RequeueAfter != tc.wantRequeue {
				t.Errorf("res=%+v err=%v, want requeue %v and no error", res, err, tc.wantRequeue)
			}
			if ready != "Enforced" || len(rec.Events) != 0 {
				t.Errorf("ready=%q events=%d, want Ready untouched and no events", ready, len(rec.Events))
			}
		})
	}
}
