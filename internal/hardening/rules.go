package hardening

import (
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/nrndev/netsec/api/v1alpha1"
)

// ContainerPlan holds the fields to set on one container. Zero values mean "leave alone".
type ContainerPlan struct {
	Name string
	Init bool

	AllowPrivilegeEscalation bool
	DropAllCapabilities      bool
	ReadOnlyRootFilesystem   bool
	// Requests and Limits hold only the resources we set.
	Requests corev1.ResourceList
	Limits   corev1.ResourceList
}

func (c ContainerPlan) empty() bool {
	return !c.AllowPrivilegeEscalation && !c.DropAllCapabilities && !c.ReadOnlyRootFilesystem &&
		len(c.Requests) == 0 && len(c.Limits) == 0
}

// TemplatePlan is everything we would set on one pod template.
type TemplatePlan struct {
	SeccompRuntimeDefault bool
	RunAsNonRoot          bool
	Containers            []ContainerPlan
	// Changes are "path: old → new" lines, in a stable order.
	Changes []string
	// Warnings are risks we saw but will not fix.
	Warnings []string
}

const unset = "<unset>"

// PlanTemplate applies the field and resource rules of design §4.2 to a pod template.
// It only fills unset values and never edits tpl.
// A resource that a LimitRange in lrs gives a default is left alone (see LimitRangeCover).
func PlanTemplate(tpl *corev1.PodTemplateSpec, sc v1alpha1.StrictSecurity, res v1alpha1.DefaultResources, lrs []corev1.LimitRange) TemplatePlan {
	var p TemplatePlan
	covered := LimitRangeCover(lrs)
	if res.Enabled == nil || *res.Enabled {
		for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
			if lr, ok := covered[name]; ok {
				p.Warnings = append(p.Warnings, fmt.Sprintf("%s defaults left to LimitRange %q", name, lr))
			}
		}
	}
	spec := &tpl.Spec
	windows := spec.OS != nil && spec.OS.Name == corev1.Windows
	if windows {
		p.Warnings = append(p.Warnings, "Windows pod: securityContext fields are not changed")
	} else {
		p.planPod(spec, sc)
	}
	for _, init := range []bool{true, false} {
		list := spec.Containers
		if init {
			list = spec.InitContainers
		}
		for i := range list {
			cp := ContainerPlan{Name: list[i].Name, Init: init}
			if !windows {
				p.planContainerSecurity(&cp, &list[i], sc)
			}
			if res.Enabled == nil || *res.Enabled {
				p.planResources(&cp, &list[i], res, covered)
			}
			if !cp.empty() {
				p.Containers = append(p.Containers, cp)
			}
		}
	}
	return p
}

func containerPath(init bool, name string) string {
	if init {
		return fmt.Sprintf("initContainers[%s]", name)
	}
	return fmt.Sprintf("containers[%s]", name)
}

func allContainers(spec *corev1.PodSpec) []corev1.Container {
	return append(slices.Clone(spec.InitContainers), spec.Containers...)
}

// change records that an unset field will be set to now.
func (p *TemplatePlan) change(path, now string) {
	p.Changes = append(p.Changes, fmt.Sprintf("%s: %s → %s", path, unset, now))
}

func (p *TemplatePlan) planPod(spec *corev1.PodSpec, opt v1alpha1.StrictSecurity) {
	const seccomp = "template.spec.securityContext.seccompProfile.type"
	podSC := spec.SecurityContext
	if podSC != nil && podSC.SeccompProfile != nil {
		if podSC.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined {
			p.Warnings = append(p.Warnings, seccomp+" is Unconfined; not changed")
		}
	} else {
		// A container's own profile still wins for that container.
		p.SeccompRuntimeDefault = true
		p.change(seccomp, string(corev1.SeccompProfileTypeRuntimeDefault))
	}
	for _, c := range allContainers(spec) {
		if sp := containerSeccomp(c); sp != nil && sp.Type == corev1.SeccompProfileTypeUnconfined {
			p.Warnings = append(p.Warnings, fmt.Sprintf("%s.securityContext.seccompProfile.type is Unconfined; not changed", c.Name))
		}
	}

	if !opt.RunAsNonRoot || (podSC != nil && podSC.RunAsNonRoot != nil) {
		return
	}
	if why := rootReason(spec); why != "" {
		p.Warnings = append(p.Warnings, "template.spec.securityContext.runAsNonRoot not set: "+why)
		return
	}
	p.RunAsNonRoot = true
	p.change("template.spec.securityContext.runAsNonRoot", "true")
}

func containerSeccomp(c corev1.Container) *corev1.SeccompProfile {
	if c.SecurityContext == nil {
		return nil
	}
	return c.SecurityContext.SeccompProfile
}

// rootReason says why runAsNonRoot would break the pod, or "" if it would not.
func rootReason(spec *corev1.PodSpec) string {
	if sc := spec.SecurityContext; sc != nil && sc.RunAsUser != nil && *sc.RunAsUser == 0 {
		return "the pod sets runAsUser: 0"
	}
	for _, c := range allContainers(spec) {
		sc := c.SecurityContext
		if sc == nil {
			continue
		}
		if sc.RunAsUser != nil && *sc.RunAsUser == 0 {
			return fmt.Sprintf("container %s sets runAsUser: 0", c.Name)
		}
		if sc.RunAsNonRoot != nil && !*sc.RunAsNonRoot {
			return fmt.Sprintf("container %s sets runAsNonRoot: false", c.Name)
		}
	}
	return ""
}

func (p *TemplatePlan) planContainerSecurity(cp *ContainerPlan, c *corev1.Container, opt v1alpha1.StrictSecurity) {
	path := containerPath(cp.Init, c.Name) + ".securityContext"
	sc := c.SecurityContext
	if sc == nil {
		sc = &corev1.SecurityContext{}
	}
	privileged := sc.Privileged != nil && *sc.Privileged

	if sc.AllowPrivilegeEscalation == nil {
		if why := privilegeReason(sc); why != "" {
			p.Warnings = append(p.Warnings, fmt.Sprintf("%s.allowPrivilegeEscalation not set: %s", path, why))
		} else {
			cp.AllowPrivilegeEscalation = true
			p.change(path+".allowPrivilegeEscalation", "false")
		}
	}

	if opt.DropAllCapabilities {
		switch {
		case privileged:
			p.Warnings = append(p.Warnings, path+".capabilities.drop not set: container is privileged")
		case sc.Capabilities != nil && len(sc.Capabilities.Drop) > 0:
			if !slices.Contains(sc.Capabilities.Drop, "ALL") {
				p.Warnings = append(p.Warnings, path+".capabilities.drop is already set without ALL; not changed")
			}
		default:
			cp.DropAllCapabilities = true
			p.change(path+".capabilities.drop", "[ALL]")
		}
	}

	if opt.ReadOnlyRootFilesystem && sc.ReadOnlyRootFilesystem == nil {
		cp.ReadOnlyRootFilesystem = true
		p.change(path+".readOnlyRootFilesystem", "true")
	}
}

// privilegeReason says why allowPrivilegeEscalation: false is not allowed, or "".
// The API rejects it for privileged containers and for containers that add SYS_ADMIN.
func privilegeReason(sc *corev1.SecurityContext) string {
	if sc.Privileged != nil && *sc.Privileged {
		return "container is privileged"
	}
	if sc.Capabilities != nil && (slices.Contains(sc.Capabilities.Add, "SYS_ADMIN") || slices.Contains(sc.Capabilities.Add, "CAP_SYS_ADMIN")) {
		return "container adds SYS_ADMIN"
	}
	return ""
}

func (p *TemplatePlan) planResources(cp *ContainerPlan, c *corev1.Container, res v1alpha1.DefaultResources, covered map[corev1.ResourceName]string) {
	_, cpuCovered := covered[corev1.ResourceCPU]
	_, memCovered := covered[corev1.ResourceMemory]
	path := containerPath(cp.Init, c.Name) + ".resources"
	set := func(into *corev1.ResourceList, kind string, name corev1.ResourceName, q resource.Quantity) {
		if *into == nil {
			*into = corev1.ResourceList{}
		}
		(*into)[name] = q
		p.change(fmt.Sprintf("%s.%s.%s", path, kind, name), q.String())
	}
	existing := func(l corev1.ResourceList, name corev1.ResourceName) (resource.Quantity, bool) {
		q, ok := l[name]
		return q, ok
	}

	reqMem, haveReqMem := existing(c.Resources.Requests, corev1.ResourceMemory)
	limMem, haveLimMem := existing(c.Resources.Limits, corev1.ResourceMemory)
	limCPU, haveLimCPU := existing(c.Resources.Limits, corev1.ResourceCPU)

	if _, ok := existing(c.Resources.Requests, corev1.ResourceCPU); !ok && !cpuCovered && !res.Requests.CPU.IsZero() {
		q := res.Requests.CPU
		if haveLimCPU && limCPU.Cmp(q) < 0 {
			q = limCPU
		}
		set(&cp.Requests, "requests", corev1.ResourceCPU, q)
	}
	if !haveReqMem && !memCovered && !res.Requests.Memory.IsZero() {
		reqMem = res.Requests.Memory
		if haveLimMem && limMem.Cmp(reqMem) < 0 {
			reqMem = limMem
		}
		haveReqMem = true
		set(&cp.Requests, "requests", corev1.ResourceMemory, reqMem)
	}
	if !haveLimMem && !memCovered && !res.Limits.Memory.IsZero() {
		q := res.Limits.Memory
		if haveReqMem && reqMem.Cmp(q) > 0 {
			q = reqMem
		}
		set(&cp.Limits, "limits", corev1.ResourceMemory, q)
	}
	// A CPU limit is never set (design §4.2).
}

// LimitRangeCover says which of cpu and memory a namespace LimitRange gives a default to,
// and the name of the first such LimitRange by name. A resource is covered when a Container
// item has it in default or defaultRequest. The API server already copies max into default
// and min into defaultRequest when those are unset, so only the stored values are read.
func LimitRangeCover(lrs []corev1.LimitRange) map[corev1.ResourceName]string {
	sorted := slices.Clone(lrs)
	slices.SortFunc(sorted, func(a, b corev1.LimitRange) int { return strings.Compare(a.Name, b.Name) })
	covered := map[corev1.ResourceName]string{}
	for _, lr := range sorted {
		for _, item := range lr.Spec.Limits {
			if item.Type != corev1.LimitTypeContainer {
				continue
			}
			for _, l := range []corev1.ResourceList{item.Default, item.DefaultRequest} {
				for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
					if _, ok := l[name]; ok && covered[name] == "" {
						covered[name] = lr.Name
					}
				}
			}
		}
	}
	return covered
}
