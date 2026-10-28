package hardening

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/nrndev/netsec/api/v1alpha1"
)

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApplyConfig(t *testing.T) {
	tpl := tplWith(corev1.Container{})
	tpl.Spec.InitContainers = []corev1.Container{{Name: initName}}
	plan := PlanTemplate(tpl, allOn(), defaults(), nil)

	const podSpec = `{"securityContext":{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}},` +
		`"containers":[{"name":"gateway","resources":{"limits":{"memory":"512Mi"},"requests":{"cpu":"100m","memory":"128Mi"}},` +
		`"securityContext":{"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"allowPrivilegeEscalation":false}}],` +
		`"initContainers":[{"name":"setup","resources":{"limits":{"memory":"512Mi"},"requests":{"cpu":"100m","memory":"128Mi"}},` +
		`"securityContext":{"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"allowPrivilegeEscalation":false}}]}`
	const tplJSON = `{"spec":` + podSpec + `}`
	meta := func(kind, api string) string {
		return `{"kind":"` + kind + `","apiVersion":"` + api + `","metadata":{"name":"web","namespace":"tenant-a"},`
	}
	want := map[v1alpha1.WorkloadKind]string{
		v1alpha1.KindDeployment:  meta("Deployment", "apps/v1") + `"spec":{"template":` + tplJSON + `}}`,
		v1alpha1.KindStatefulSet: meta("StatefulSet", "apps/v1") + `"spec":{"template":` + tplJSON + `}}`,
		v1alpha1.KindDaemonSet:   meta("DaemonSet", "apps/v1") + `"spec":{"template":` + tplJSON + `}}`,
		v1alpha1.KindCronJob:     meta("CronJob", "batch/v1") + `"spec":{"jobTemplate":{"spec":{"template":` + tplJSON + `}}}}`,
	}
	for kind, w := range want {
		t.Run(string(kind), func(t *testing.T) {
			ac, err := ApplyConfig(kind, nsApp, "web", plan)
			if err != nil {
				t.Fatal(err)
			}
			sameJSON(t, asJSON(t, ac), w)
		})
	}
}

func TestApplyConfigOnlyListsChangedContainers(t *testing.T) {
	tpl := &corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{
		{Name: "done", SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: new(false)}},
		{Name: "todo"},
	}}}
	plan := PlanTemplate(tpl, v1alpha1.StrictSecurity{}, off(), nil)
	ac, err := ApplyConfig(v1alpha1.KindDeployment, nsApp, "web", plan)
	if err != nil {
		t.Fatal(err)
	}
	got := asJSON(t, ac)
	if !strings.Contains(got, `"name":"todo"`) || strings.Contains(got, `"name":"done"`) {
		t.Errorf("containers in apply config: %s", got)
	}
}

// sameJSON compares two JSON documents ignoring key order.
func sameJSON(t *testing.T, got, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal([]byte(got), &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("JSON differs\n got: %s\nwant: %s", got, want)
	}
}

func TestEmptyApplyConfigIsIdentityOnly(t *testing.T) {
	for kind, want := range map[v1alpha1.WorkloadKind]string{
		v1alpha1.KindDeployment:  `{"kind":"Deployment","apiVersion":"apps/v1","metadata":{"name":"web","namespace":"tenant-a"}}`,
		v1alpha1.KindStatefulSet: `{"kind":"StatefulSet","apiVersion":"apps/v1","metadata":{"name":"web","namespace":"tenant-a"}}`,
		v1alpha1.KindDaemonSet:   `{"kind":"DaemonSet","apiVersion":"apps/v1","metadata":{"name":"web","namespace":"tenant-a"}}`,
		v1alpha1.KindCronJob:     `{"kind":"CronJob","apiVersion":"batch/v1","metadata":{"name":"web","namespace":"tenant-a"}}`,
	} {
		ac, err := EmptyApplyConfig(kind, nsApp, "web")
		if err != nil {
			t.Fatal(err)
		}
		sameJSON(t, asJSON(t, ac), want)
	}
}

func TestApplyConfigRejectsUnknownKind(t *testing.T) {
	if _, err := ApplyConfig("Job", nsApp, "web", TemplatePlan{}); err == nil {
		t.Error("ApplyConfig: want an error for Job")
	}
	if _, err := EmptyApplyConfig("Job", nsApp, "web"); err == nil {
		t.Error("EmptyApplyConfig: want an error for Job")
	}
}
