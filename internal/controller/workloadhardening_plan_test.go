package controller

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	netsecv1alpha1 "github.com/nrndev/netsec/api/v1alpha1"
	"github.com/nrndev/netsec/internal/hardening"
)

// The plan dry-runs every patch (US5.3). A change the API server rejects must show up as
// Failed with a WouldFail reason; any other error must stop the plan instead of being hidden.
// The patch must be a dry run: a real one would change the workload while only planning.
func TestPlanTargetDryRunsAndReportsRejections(t *testing.T) {
	invalid := apierrors.NewInvalid(schema.GroupKind{Group: "apps", Kind: "Deployment"}, "web", nil)
	for name, tc := range map[string]struct {
		patchErr  error
		wantState netsecv1alpha1.WorkloadState
		wantErr   bool
	}{
		"accepted":            {nil, netsecv1alpha1.StatePending, false},
		"rejected by the API": {invalid, netsecv1alpha1.StateFailed, false},
		"server error":        {apierrors.NewInternalError(errors.New("boom")), "", true},
	} {
		t.Run(name, func(t *testing.T) {
			var dryRuns []bool
			c := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithInterceptorFuncs(interceptor.Funcs{
				Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, opts ...client.PatchOption) error {
					po := &client.PatchOptions{}
					po.ApplyOptions(opts)
					dryRuns = append(dryRuns, slices.Equal(po.DryRun, []string{metav1.DryRunAll}))
					return tc.patchErr
				},
			}).Build()
			p := &pass{
				r:       &WorkloadHardeningReconciler{Client: c},
				wh:      &netsecv1alpha1.WorkloadHardening{Spec: netsecv1alpha1.WorkloadHardeningSpec{}},
				manager: "netsec-hardening-test",
			}
			cand := hardening.Candidate{Kind: string(netsecv1alpha1.KindDeployment), Namespace: "ns", Name: "web"}
			tpl := &corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}

			w, err := p.planTarget(context.Background(), cand, found{template: tpl, generation: 3})

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error: %v", err, tc.wantErr)
			}
			if !tc.wantErr && w.State != tc.wantState {
				t.Errorf("state = %q, want %q", w.State, tc.wantState)
			}
			if tc.wantState == netsecv1alpha1.StateFailed && !strings.HasPrefix(w.Reason, "WouldFail: ") {
				t.Errorf("reason = %q, want a WouldFail reason", w.Reason)
			}
			if len(dryRuns) != 1 || !dryRuns[0] {
				t.Errorf("patches sent (true = dry run): %v, want exactly one dry run", dryRuns)
			}
		})
	}
}
