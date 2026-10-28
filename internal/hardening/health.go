package hardening

import (
	"fmt"
	"slices"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// HealthState is the health gate's verdict for one workload.
type HealthState string

const (
	Healthy     HealthState = "Healthy"
	Progressing HealthState = "Progressing"
	// Unverified means a rollout cannot be checked (paused, 0 replicas, OnDelete, CronJob).
	Unverified HealthState = "Unverified"
	Failed     HealthState = "Failed"
)

// Health is a verdict and, for Failed and Unverified, the reason.
type Health struct {
	State  HealthState
	Reason string
}

// unschedulableGrace is how long a new pod may stay Unschedulable before the gate fails.
// It is not zero because a cluster autoscaler may add a node that fits the pod.
const unschedulableGrace = 60 * time.Second

// failingWaitReasons are container waiting reasons that mean the new pods will not start.
var failingWaitReasons = []string{"CreateContainerConfigError", "CreateContainerError", "RunContainerError", "CrashLoopBackOff"}

// CheckHealth is the health gate of design §4.4. obj is a *appsv1.Deployment, StatefulSet,
// DaemonSet or *batchv1.CronJob. pods are the workload's pods; only those created after
// appliedAt count. now is a parameter so tests need no clock.
func CheckHealth(obj runtime.Object, pods []corev1.Pod, appliedAt, now time.Time, timeout time.Duration) (Health, error) {
	var h Health
	switch w := obj.(type) {
	case *batchv1.CronJob:
		return Health{Unverified, "the change applies to the next run"}, nil
	case *appsv1.Deployment:
		h = deploymentState(w)
	case *appsv1.StatefulSet:
		h = statefulSetState(w)
	case *appsv1.DaemonSet:
		h = daemonSetState(w)
	default:
		return Health{}, fmt.Errorf("cannot check the health of %T", obj)
	}
	if h.State == Unverified {
		return h, nil
	}
	if reason := podFailure(pods, appliedAt, now); reason != "" {
		return Health{Failed, reason}, nil
	}
	if h.State != Progressing {
		return h, nil
	}
	if now.Sub(appliedAt) > timeout {
		return Health{Failed, fmt.Sprintf("rollout did not finish within %s", timeout)}, nil
	}
	return h, nil
}

var progressing = Health{State: Progressing}

func replicasOrOne(r *int32) int32 {
	if r == nil {
		return 1
	}
	return *r
}

func deploymentState(d *appsv1.Deployment) Health {
	want := replicasOrOne(d.Spec.Replicas)
	switch {
	case want == 0:
		return Health{Unverified, "replicas is 0, so no pods roll out"}
	case d.Spec.Paused:
		return Health{Unverified, "the Deployment is paused"}
	case d.Status.ObservedGeneration < d.Generation:
		return progressing
	}
	for _, c := range d.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing && c.Reason == "ProgressDeadlineExceeded" {
			return Health{Failed, "ProgressDeadlineExceeded"}
		}
	}
	s := d.Status
	if s.Replicas == want && s.UpdatedReplicas == want && s.AvailableReplicas == want {
		return Health{State: Healthy}
	}
	return progressing
}

func statefulSetState(s *appsv1.StatefulSet) Health {
	switch {
	case s.Spec.UpdateStrategy.Type == appsv1.OnDeleteStatefulSetStrategyType:
		return Health{Unverified, "updateStrategy is OnDelete, so pods are not replaced"}
	case s.Spec.UpdateStrategy.RollingUpdate != nil && s.Spec.UpdateStrategy.RollingUpdate.Partition != nil && *s.Spec.UpdateStrategy.RollingUpdate.Partition > 0:
		return Health{Unverified, "rollingUpdate partition is above 0, so not all pods are replaced"}
	case s.Status.ObservedGeneration < s.Generation:
		return progressing
	}
	want := replicasOrOne(s.Spec.Replicas)
	if s.Status.UpdateRevision == s.Status.CurrentRevision && s.Status.Replicas == want && s.Status.ReadyReplicas == want {
		return Health{State: Healthy}
	}
	return progressing
}

func daemonSetState(d *appsv1.DaemonSet) Health {
	switch {
	case d.Spec.UpdateStrategy.Type == appsv1.OnDeleteDaemonSetStrategyType:
		return Health{Unverified, "updateStrategy is OnDelete, so pods are not replaced"}
	case d.Status.DesiredNumberScheduled == 0:
		return Health{Unverified, "no pods are scheduled, so nothing rolls out"}
	case d.Status.ObservedGeneration < d.Generation:
		return progressing
	}
	s := d.Status
	if s.UpdatedNumberScheduled == s.DesiredNumberScheduled && s.NumberAvailable == s.DesiredNumberScheduled {
		return Health{State: Healthy}
	}
	return progressing
}

// podFailure returns a reason if a pod created after appliedAt is failing, else "".
// Pod creation times have one-second resolution, so appliedAt is truncated the same
// way; a pod made in the same second as the patch still counts.
func podFailure(pods []corev1.Pod, appliedAt, now time.Time) string {
	cutoff := appliedAt.Truncate(time.Second)
	for _, p := range pods {
		if p.CreationTimestamp.Time.Before(cutoff) {
			continue
		}
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason == corev1.PodReasonUnschedulable &&
				now.Sub(c.LastTransitionTime.Time) > unschedulableGrace {
				return "Unschedulable: " + c.Message
			}
		}
		statuses := append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...)
		for _, cs := range statuses {
			if w := cs.State.Waiting; w != nil && isFailingWait(w.Reason) {
				return fmt.Sprintf("pod %s container %s: %s", p.Name, cs.Name, w.Reason)
			}
			if t := cs.LastTerminationState.Terminated; t != nil && t.Reason == "OOMKilled" {
				return fmt.Sprintf("pod %s container %s: OOMKilled", p.Name, cs.Name)
			}
			if t := cs.State.Terminated; t != nil && t.Reason == "OOMKilled" {
				return fmt.Sprintf("pod %s container %s: OOMKilled", p.Name, cs.Name)
			}
		}
	}
	return ""
}

func isFailingWait(reason string) bool { return slices.Contains(failingWaitReasons, reason) }

// StuckPods returns the pods of the given StatefulSet revision that are not Ready.
// The controller deletes them after a revert, or the StatefulSet stays stuck
// ("forced rollback"). Pass the revision recorded before the revert: afterwards the
// StatefulSet's updateRevision points at the restored one. An empty revision matches nothing.
func StuckPods(pods []corev1.Pod, revision string) []corev1.Pod {
	if revision == "" {
		return nil
	}
	var out []corev1.Pod
	for _, p := range pods {
		if p.Labels[appsv1.ControllerRevisionHashLabelKey] == revision && !podReady(p) {
			out = append(out, p)
		}
	}
	return out
}

func podReady(p corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
