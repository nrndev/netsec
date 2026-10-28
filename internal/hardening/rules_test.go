package hardening

import (
	"maps"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nrndev/netsec/api/v1alpha1"
)

const (
	cName   = "gateway"
	cpuKey  = corev1.ResourceCPU
	memKey  = corev1.ResourceMemory
	seccomp = "template.spec.securityContext.seccompProfile.type: <unset> → RuntimeDefault"
)

func q(s string) resource.Quantity { return resource.MustParse(s) }

func defaults() v1alpha1.DefaultResources {
	on := true
	return v1alpha1.DefaultResources{
		Enabled:  &on,
		Requests: v1alpha1.ResourceRequests{CPU: q("100m"), Memory: q("128Mi")},
		Limits:   v1alpha1.ResourceLimits{Memory: q("512Mi")},
	}
}

// custom is defaults the user overrode in the spec.
func custom() v1alpha1.DefaultResources {
	d := defaults()
	d.Requests = v1alpha1.ResourceRequests{CPU: q("250m"), Memory: q("256Mi")}
	d.Limits = v1alpha1.ResourceLimits{Memory: q("1Gi")}
	return d
}

func off() v1alpha1.DefaultResources { return v1alpha1.DefaultResources{} }

func allOn() v1alpha1.StrictSecurity {
	return v1alpha1.StrictSecurity{RunAsNonRoot: true, DropAllCapabilities: true, ReadOnlyRootFilesystem: true}
}

func tplWith(c corev1.Container) *corev1.PodTemplateSpec {
	c.Name = cName
	return &corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{c}}}
}

func csc(sc corev1.SecurityContext) corev1.Container { return corev1.Container{SecurityContext: &sc} }

func hasChange(p TemplatePlan, want string) bool { return slices.Contains(p.Changes, want) }

func hasFinding(p TemplatePlan, sub string) bool {
	return slices.ContainsFunc(p.Warnings, func(f string) bool { return strings.Contains(f, sub) })
}

func TestAlwaysOnFields(t *testing.T) {
	p := PlanTemplate(tplWith(corev1.Container{}), v1alpha1.StrictSecurity{}, off(), nil)
	want := []string{seccomp, "containers[gateway].securityContext.allowPrivilegeEscalation: <unset> → false"}
	if !slices.Equal(p.Changes, want) {
		t.Fatalf("changes = %v, want %v", p.Changes, want)
	}
	if p.RunAsNonRoot || p.Containers[0].DropAllCapabilities || p.Containers[0].ReadOnlyRootFilesystem {
		t.Errorf("opt-in fields were set without opt-in: %+v", p)
	}
}

func TestOptInFields(t *testing.T) {
	p := PlanTemplate(tplWith(corev1.Container{}), allOn(), off(), nil)
	for _, w := range []string{
		"template.spec.securityContext.runAsNonRoot: <unset> → true",
		"containers[gateway].securityContext.capabilities.drop: <unset> → [ALL]",
		"containers[gateway].securityContext.readOnlyRootFilesystem: <unset> → true",
	} {
		if !hasChange(p, w) {
			t.Errorf("missing change %q in %v", w, p.Changes)
		}
	}
}

func TestInitContainersAreCovered(t *testing.T) {
	tpl := tplWith(corev1.Container{})
	tpl.Spec.InitContainers = []corev1.Container{{Name: initName}}
	p := PlanTemplate(tpl, allOn(), defaults(), nil)
	if !hasChange(p, "initContainers[setup].securityContext.allowPrivilegeEscalation: <unset> → false") ||
		!hasChange(p, "initContainers[setup].resources.requests.memory: <unset> → 128Mi") {
		t.Errorf("init container not planned: %v", p.Changes)
	}
}

func TestSkipsAndWarnings(t *testing.T) {
	yes, no, root := true, false, int64(0)
	cases := []struct {
		name        string
		tpl         *corev1.PodTemplateSpec
		notChanged  string // a path substring that must not appear in Changes
		warning     string // substring expected in Warnings
		changeCount int    // -1 = don't check
	}{
		{wordPrivileged, tplWith(csc(corev1.SecurityContext{Privileged: &yes})), keyAPE, wordPrivileged, -1},
		{capSysAdmin, tplWith(csc(corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: []corev1.Capability{capSysAdmin}}})), keyAPE, capSysAdmin, -1},
		{"CAP_SYS_ADMIN", tplWith(csc(corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"CAP_SYS_ADMIN"}}})), keyAPE, "SYS_ADMIN", -1},
		{"privileged blocks drop ALL", tplWith(csc(corev1.SecurityContext{Privileged: &yes})), "capabilities", "capabilities.drop not set", -1},
		{"existing drop is kept", tplWith(csc(corev1.SecurityContext{Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"NET_RAW"}}})), "capabilities", "without ALL", -1},
		{"explicit false escalation is kept", tplWith(csc(corev1.SecurityContext{AllowPrivilegeEscalation: &no})), keyAPE, "", -1},
		{"explicit true escalation is kept", tplWith(csc(corev1.SecurityContext{AllowPrivilegeEscalation: &yes})), keyAPE, "", -1},
		{"explicit readOnly false is kept", tplWith(csc(corev1.SecurityContext{ReadOnlyRootFilesystem: &no})), "readOnlyRootFilesystem", "", -1},
		{"container runAsUser 0 blocks runAsNonRoot", tplWith(csc(corev1.SecurityContext{RunAsUser: &root})), "runAsNonRoot", "runAsUser: 0", -1},
		{"container runAsNonRoot false blocks it", tplWith(csc(corev1.SecurityContext{RunAsNonRoot: &no})), "runAsNonRoot", "runAsNonRoot: false", -1},
		{"container seccomp is kept", tplWith(csc(corev1.SecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost}})), "containers[gateway].securityContext.seccompProfile", "", -1},
		{"container Unconfined is reported", tplWith(csc(corev1.SecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}})), "containers[gateway].securityContext.seccompProfile", "Unconfined", -1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := PlanTemplate(c.tpl, allOn(), off(), nil)
			for _, ch := range p.Changes {
				if strings.Contains(ch, c.notChanged) {
					t.Errorf("unexpected change %q", ch)
				}
			}
			if c.warning != "" && !hasFinding(p, c.warning) {
				t.Errorf("warnings = %v, want one containing %q", p.Warnings, c.warning)
			}
			if c.warning == "" && len(p.Warnings) != 0 {
				t.Errorf("unexpected warnings %v", p.Warnings)
			}
		})
	}
}

func TestPodLevelBlockers(t *testing.T) {
	root := int64(0)
	podRoot := tplWith(corev1.Container{})
	podRoot.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsUser: &root}
	p := PlanTemplate(podRoot, allOn(), off(), nil)
	if p.RunAsNonRoot || !hasFinding(p, "pod sets runAsUser: 0") {
		t.Errorf("pod runAsUser 0 must block runAsNonRoot: %+v", p)
	}

	explicit := false
	podNoRoot := tplWith(corev1.Container{})
	podNoRoot.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: &explicit}
	if p := PlanTemplate(podNoRoot, allOn(), off(), nil); p.RunAsNonRoot || len(p.Warnings) != 0 {
		t.Errorf("explicit pod runAsNonRoot must be left alone: %+v", p)
	}

	unconf := tplWith(corev1.Container{})
	unconf.Spec.SecurityContext = &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}}
	p = PlanTemplate(unconf, allOn(), off(), nil)
	if p.SeccompRuntimeDefault || !hasFinding(p, "Unconfined") {
		t.Errorf("pod-level Unconfined must be reported, not changed: %+v", p)
	}
}

func TestWindowsSkipsSecurityContextOnly(t *testing.T) {
	tpl := tplWith(corev1.Container{})
	tpl.Spec.OS = &corev1.PodOS{Name: corev1.Windows}
	p := PlanTemplate(tpl, allOn(), defaults(), nil)
	for _, ch := range p.Changes {
		if strings.Contains(ch, "securityContext") {
			t.Errorf("Windows pod got %q", ch)
		}
	}
	if !hasChange(p, "containers[gateway].resources.requests.memory: <unset> → 128Mi") {
		t.Errorf("resources should still apply: %v", p.Changes)
	}
	if !hasFinding(p, "Windows") {
		t.Errorf("warnings = %v", p.Warnings)
	}
}

func rl(cpu, mem string) corev1.ResourceList {
	l := corev1.ResourceList{}
	if cpu != "" {
		l[cpuKey] = q(cpu)
	}
	if mem != "" {
		l[memKey] = q(mem)
	}
	return l
}

func TestResourceRules(t *testing.T) {
	cases := []struct {
		name         string
		have         corev1.ResourceRequirements
		def          v1alpha1.DefaultResources
		wantRequests corev1.ResourceList
		wantLimits   corev1.ResourceList
	}{
		{"nothing set", corev1.ResourceRequirements{}, defaults(), rl("100m", "128Mi"), rl("", "512Mi")},
		{"values from the spec override the defaults", corev1.ResourceRequirements{}, custom(), rl("250m", "256Mi"), rl("", "1Gi")},
		{"disabled", corev1.ResourceRequirements{}, off(), nil, nil},
		{"request clamped to a smaller memory limit", corev1.ResourceRequirements{Limits: rl("", "64Mi")}, defaults(), rl("100m", "64Mi"), nil},
		{"request clamped to a smaller cpu limit", corev1.ResourceRequirements{Limits: rl("50m", "")}, defaults(), rl("50m", "128Mi"), rl("", "512Mi")},
		{"memory limit raised to a larger request", corev1.ResourceRequirements{Requests: rl("", "1Gi")}, defaults(), rl("100m", ""), rl("", "1Gi")},
		{"never lowers existing values", corev1.ResourceRequirements{Requests: rl("2", "4Gi"), Limits: rl("", "8Gi")}, defaults(), nil, nil},
		{"never sets a cpu limit", corev1.ResourceRequirements{Requests: rl("", "128Mi")}, defaults(), rl("100m", ""), rl("", "512Mi")},
		{"existing cpu limit is untouched", corev1.ResourceRequirements{Requests: rl("10m", "128Mi"), Limits: rl("1", "")}, defaults(), nil, rl("", "512Mi")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := PlanTemplate(tplWith(corev1.Container{Resources: c.have}), v1alpha1.StrictSecurity{}, c.def, nil)
			var got ContainerPlan
			if len(p.Containers) > 0 {
				got = p.Containers[0]
			}
			if !equalList(got.Requests, c.wantRequests) || !equalList(got.Limits, c.wantLimits) {
				t.Errorf("requests=%v limits=%v, want requests=%v limits=%v", got.Requests, got.Limits, c.wantRequests, c.wantLimits)
			}
			if _, ok := got.Limits[cpuKey]; ok {
				t.Error("a CPU limit was set")
			}
		})
	}
}

func equalList(a, b corev1.ResourceList) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if o, ok := b[k]; !ok || v.Cmp(o) != 0 {
			return false
		}
	}
	return true
}

// applyPlan writes a plan into a template, the way the API server would merge our apply.
func applyPlan(tpl *corev1.PodTemplateSpec, p TemplatePlan) {
	if tpl.Spec.SecurityContext == nil {
		tpl.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}
	if p.SeccompRuntimeDefault {
		tpl.Spec.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
	}
	if p.RunAsNonRoot {
		yes := true
		tpl.Spec.SecurityContext.RunAsNonRoot = &yes
	}
	for _, cp := range p.Containers {
		list := tpl.Spec.Containers
		if cp.Init {
			list = tpl.Spec.InitContainers
		}
		for i := range list {
			if list[i].Name != cp.Name {
				continue
			}
			c := &list[i]
			if c.SecurityContext == nil {
				c.SecurityContext = &corev1.SecurityContext{}
			}
			no, yes := false, true
			if cp.AllowPrivilegeEscalation {
				c.SecurityContext.AllowPrivilegeEscalation = &no
			}
			if cp.DropAllCapabilities {
				c.SecurityContext.Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}
			}
			if cp.ReadOnlyRootFilesystem {
				c.SecurityContext.ReadOnlyRootFilesystem = &yes
			}
			if c.Resources.Requests == nil && len(cp.Requests) > 0 {
				c.Resources.Requests = corev1.ResourceList{}
			}
			if c.Resources.Limits == nil && len(cp.Limits) > 0 {
				c.Resources.Limits = corev1.ResourceList{}
			}
			maps.Copy(c.Resources.Requests, cp.Requests)
			maps.Copy(c.Resources.Limits, cp.Limits)
		}
	}
}

func TestPlanIsIdempotent(t *testing.T) {
	yes := true
	cases := map[string]*corev1.PodTemplateSpec{
		"bare":         tplWith(corev1.Container{}),
		"limit only":   tplWith(corev1.Container{Resources: corev1.ResourceRequirements{Limits: rl("50m", "64Mi")}}),
		"big request":  tplWith(corev1.Container{Resources: corev1.ResourceRequirements{Requests: rl("", "1Gi")}}),
		wordPrivileged: tplWith(csc(corev1.SecurityContext{Privileged: &yes})),
	}
	cases["with init"] = tplWith(corev1.Container{})
	cases["with init"].Spec.InitContainers = []corev1.Container{{Name: initName}}
	for name, tpl := range cases {
		t.Run(name, func(t *testing.T) {
			first := PlanTemplate(tpl, allOn(), defaults(), nil)
			if len(first.Changes) == 0 {
				t.Fatal("test template needs at least one change")
			}
			applyPlan(tpl, first)
			second := PlanTemplate(tpl, allOn(), defaults(), nil)
			if len(second.Changes) != 0 || len(second.Containers) != 0 || second.SeccompRuntimeDefault || second.RunAsNonRoot {
				t.Errorf("second plan still has changes: %v", second.Changes)
			}
		})
	}
}

func TestPlanDoesNotEditTheTemplate(t *testing.T) {
	tpl := tplWith(corev1.Container{})
	_ = PlanTemplate(tpl, allOn(), defaults(), nil)
	if tpl.Spec.SecurityContext != nil || tpl.Spec.Containers[0].SecurityContext != nil || tpl.Spec.Containers[0].Resources.Requests != nil {
		t.Error("PlanTemplate edited its input")
	}
}

// The pod-level profile is set even when a container has its own; Unconfined containers are reported.
func TestSeccompMixedContainers(t *testing.T) {
	tpl := tplWith(csc(corev1.SecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}}))
	tpl.Spec.Containers = append(tpl.Spec.Containers, corev1.Container{Name: "plain"})
	p := PlanTemplate(tpl, v1alpha1.StrictSecurity{}, off(), nil)
	if !p.SeccompRuntimeDefault || !hasChange(p, seccomp) {
		t.Errorf("pod-level RuntimeDefault not set: %v", p.Changes)
	}
	if !hasFinding(p, "gateway.securityContext.seccompProfile.type is Unconfined") || hasFinding(p, "plain") {
		t.Errorf("warnings = %v", p.Warnings)
	}
}

func limitRange(name string, typ corev1.LimitType, def, defReq corev1.ResourceList) corev1.LimitRange {
	return corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{Type: typ, Default: def, DefaultRequest: defReq}}},
	}
}

func TestLimitRangeCover(t *testing.T) {
	mem := corev1.ResourceList{memKey: q("256Mi")}
	cpu := corev1.ResourceList{cpuKey: q("100m")}
	cases := []struct {
		name string
		lrs  []corev1.LimitRange
		want map[corev1.ResourceName]string
	}{
		{"none", nil, map[corev1.ResourceName]string{}},
		{"memory only", []corev1.LimitRange{limitRange("lr", corev1.LimitTypeContainer, mem, nil)}, map[corev1.ResourceName]string{memKey: "lr"}},
		{"cpu through defaultRequest", []corev1.LimitRange{limitRange("lr", corev1.LimitTypeContainer, nil, cpu)}, map[corev1.ResourceName]string{cpuKey: "lr"}},
		{"both", []corev1.LimitRange{limitRange("lr", corev1.LimitTypeContainer, mem, cpu)}, map[corev1.ResourceName]string{cpuKey: "lr", memKey: "lr"}},
		{"Pod item ignored", []corev1.LimitRange{limitRange("lr", corev1.LimitTypePod, mem, cpu)}, map[corev1.ResourceName]string{}},
		{"first by name is named", []corev1.LimitRange{
			limitRange("b", corev1.LimitTypeContainer, mem, nil),
			limitRange("a", corev1.LimitTypeContainer, mem, cpu),
		}, map[corev1.ResourceName]string{cpuKey: "a", memKey: "a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := LimitRangeCover(c.lrs); !maps.Equal(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestPlanTemplateSkipsCoveredResources(t *testing.T) {
	lrs := []corev1.LimitRange{limitRange("limits", corev1.LimitTypeContainer, corev1.ResourceList{memKey: q("256Mi")}, nil)}
	p := PlanTemplate(tplWith(corev1.Container{}), v1alpha1.StrictSecurity{}, defaults(), lrs)
	if len(p.Containers) != 1 || !equalList(p.Containers[0].Requests, corev1.ResourceList{cpuKey: q("100m")}) || len(p.Containers[0].Limits) != 0 {
		t.Errorf("want only the CPU request, got %+v", p.Containers)
	}
	if len(p.Warnings) != 1 || p.Warnings[0] != `memory defaults left to LimitRange "limits"` {
		t.Errorf("warnings = %v", p.Warnings)
	}
	no := false
	disabled := PlanTemplate(tplWith(corev1.Container{}), v1alpha1.StrictSecurity{}, v1alpha1.DefaultResources{Enabled: &no}, lrs)
	if len(disabled.Warnings) != 0 {
		t.Errorf("defaultResources disabled should not warn, got %v", disabled.Warnings)
	}
}
