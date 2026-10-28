package hardening

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	batchv1ac "k8s.io/client-go/applyconfigurations/batch/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"

	"github.com/nrndev/netsec/api/v1alpha1"
)

// ApplyConfig builds the server-side apply object for one workload: its identity plus
// only the fields in plan. Containers are matched by name.
func ApplyConfig(kind v1alpha1.WorkloadKind, namespace, name string, plan TemplatePlan) (runtime.ApplyConfiguration, error) {
	tpl := podTemplate(plan)
	switch kind {
	case v1alpha1.KindDeployment:
		return appsv1ac.Deployment(name, namespace).WithSpec(appsv1ac.DeploymentSpec().WithTemplate(tpl)), nil
	case v1alpha1.KindStatefulSet:
		return appsv1ac.StatefulSet(name, namespace).WithSpec(appsv1ac.StatefulSetSpec().WithTemplate(tpl)), nil
	case v1alpha1.KindDaemonSet:
		return appsv1ac.DaemonSet(name, namespace).WithSpec(appsv1ac.DaemonSetSpec().WithTemplate(tpl)), nil
	case v1alpha1.KindCronJob:
		job := batchv1ac.JobSpec().WithTemplate(tpl)
		return batchv1ac.CronJob(name, namespace).WithSpec(
			batchv1ac.CronJobSpec().WithJobTemplate(batchv1ac.JobTemplateSpec().WithSpec(job))), nil
	}
	return nil, fmt.Errorf("cannot build an apply configuration for kind %q", kind)
}

// EmptyApplyConfig is identity only. Applying it with our field manager removes
// exactly the fields that manager set, which is how revert and undo work.
func EmptyApplyConfig(kind v1alpha1.WorkloadKind, namespace, name string) (runtime.ApplyConfiguration, error) {
	switch kind {
	case v1alpha1.KindDeployment:
		return appsv1ac.Deployment(name, namespace), nil
	case v1alpha1.KindStatefulSet:
		return appsv1ac.StatefulSet(name, namespace), nil
	case v1alpha1.KindDaemonSet:
		return appsv1ac.DaemonSet(name, namespace), nil
	case v1alpha1.KindCronJob:
		return batchv1ac.CronJob(name, namespace), nil
	}
	return nil, fmt.Errorf("cannot build an apply configuration for kind %q", kind)
}

func podTemplate(plan TemplatePlan) *corev1ac.PodTemplateSpecApplyConfiguration {
	spec := corev1ac.PodSpec()
	if plan.SeccompRuntimeDefault || plan.RunAsNonRoot {
		sc := corev1ac.PodSecurityContext()
		if plan.SeccompRuntimeDefault {
			sc.WithSeccompProfile(corev1ac.SeccompProfile().WithType(corev1.SeccompProfileTypeRuntimeDefault))
		}
		if plan.RunAsNonRoot {
			sc.WithRunAsNonRoot(true)
		}
		spec.WithSecurityContext(sc)
	}
	for _, c := range plan.Containers {
		ac := corev1ac.Container().WithName(c.Name)
		if c.AllowPrivilegeEscalation || c.DropAllCapabilities || c.ReadOnlyRootFilesystem {
			sc := corev1ac.SecurityContext()
			if c.AllowPrivilegeEscalation {
				sc.WithAllowPrivilegeEscalation(false)
			}
			if c.DropAllCapabilities {
				sc.WithCapabilities(corev1ac.Capabilities().WithDrop("ALL"))
			}
			if c.ReadOnlyRootFilesystem {
				sc.WithReadOnlyRootFilesystem(true)
			}
			ac.WithSecurityContext(sc)
		}
		if len(c.Requests) > 0 || len(c.Limits) > 0 {
			r := corev1ac.ResourceRequirements()
			if len(c.Requests) > 0 {
				r.WithRequests(c.Requests)
			}
			if len(c.Limits) > 0 {
				r.WithLimits(c.Limits)
			}
			ac.WithResources(r)
		}
		if c.Init {
			spec.WithInitContainers(ac)
		} else {
			spec.WithContainers(ac)
		}
	}
	return corev1ac.PodTemplateSpec().WithSpec(spec)
}
