package hardening

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	t0      = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	timeout = 5 * time.Minute
)

func newPod(name string, created time.Time, mod func(*corev1.Pod)) corev1.Pod {
	p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: metav1.NewTime(created)}}
	if mod != nil {
		mod(&p)
	}
	return p
}

func waiting(reason string) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "c", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason}}}}
	}
}

func oomLast(p *corev1.Pod) {
	p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "c", LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: oomKilled}}}}
}

func unschedulable(since time.Time) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		p.Status.Conditions = []corev1.PodCondition{{
			Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonUnschedulable,
			Message: "0/2 nodes are available", LastTransitionTime: metav1.NewTime(since),
		}}
	}
}

func i32(n int32) *int32 { return new(n) }

func deployment(mod func(*appsv1.Deployment)) *appsv1.Deployment {
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Generation: 2},
		Spec:       appsv1.DeploymentSpec{Replicas: i32(3)},
		Status:     appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 3, UpdatedReplicas: 3, AvailableReplicas: 3},
	}
	if mod != nil {
		mod(d)
	}
	return d
}

func statefulSet(mod func(*appsv1.StatefulSet)) *appsv1.StatefulSet {
	s := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Generation: 2},
		Spec:       appsv1.StatefulSetSpec{Replicas: i32(2)},
		Status:     appsv1.StatefulSetStatus{ObservedGeneration: 2, Replicas: 2, ReadyReplicas: 2, CurrentRevision: "r2", UpdateRevision: "r2"},
	}
	if mod != nil {
		mod(s)
	}
	return s
}

func daemonSet(mod func(*appsv1.DaemonSet)) *appsv1.DaemonSet {
	d := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Generation: 2},
		Status:     appsv1.DaemonSetStatus{ObservedGeneration: 2, DesiredNumberScheduled: 3, UpdatedNumberScheduled: 3, NumberAvailable: 3},
	}
	if mod != nil {
		mod(d)
	}
	return d
}

func TestCheckHealth(t *testing.T) {
	newer := t0.Add(time.Second)
	older := t0.Add(-time.Minute)
	cases := []struct {
		name   string
		obj    runtime.Object
		pods   []corev1.Pod
		now    time.Time
		want   HealthState
		reason string
	}{
		// Deployment
		{"deployment healthy", deployment(nil), nil, t0.Add(time.Minute), Healthy, ""},
		{"deployment waiting for updated replicas", deployment(func(d *appsv1.Deployment) { d.Status.UpdatedReplicas = 1 }), nil, t0.Add(time.Minute), Progressing, ""},
		{"deployment with old pods still running", deployment(func(d *appsv1.Deployment) { d.Status.Replicas = 4 }), nil, t0.Add(time.Minute), Progressing, ""},
		{"deployment not observed yet", deployment(func(d *appsv1.Deployment) { d.Status.ObservedGeneration = 1 }), nil, t0.Add(time.Minute), Progressing, ""},
		{"deployment replicas 0 is unverified", deployment(func(d *appsv1.Deployment) { d.Spec.Replicas = i32(0) }), nil, t0.Add(time.Minute), Unverified, "replicas is 0"},
		{"deployment paused is unverified", deployment(func(d *appsv1.Deployment) { d.Spec.Paused = true }), nil, t0.Add(time.Minute), Unverified, "paused"},
		{"deployment progress deadline", deployment(func(d *appsv1.Deployment) {
			d.Status.UpdatedReplicas = 1
			d.Status.Conditions = []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded"}}
		}), nil, t0.Add(time.Minute), Failed, "ProgressDeadlineExceeded"},
		{"deployment timeout", deployment(func(d *appsv1.Deployment) { d.Status.UpdatedReplicas = 1 }), nil, t0.Add(timeout + time.Second), Failed, didNotFinish},
		{"deployment at exactly the timeout is still progressing", deployment(func(d *appsv1.Deployment) { d.Status.UpdatedReplicas = 1 }), nil, t0.Add(timeout), Progressing, ""},
		{"healthy beats timeout", deployment(nil), nil, t0.Add(time.Hour), Healthy, ""},
		// StatefulSet
		{"statefulset healthy", statefulSet(nil), nil, t0.Add(time.Minute), Healthy, ""},
		{"statefulset revisions differ", statefulSet(func(s *appsv1.StatefulSet) { s.Status.UpdateRevision = "r3" }), nil, t0.Add(time.Minute), Progressing, ""},
		{"statefulset replica not ready", statefulSet(func(s *appsv1.StatefulSet) { s.Status.ReadyReplicas = 1 }), nil, t0.Add(time.Minute), Progressing, ""},
		{"statefulset OnDelete is unverified", statefulSet(func(s *appsv1.StatefulSet) {
			s.Spec.UpdateStrategy.Type = appsv1.OnDeleteStatefulSetStrategyType
		}), nil, t0.Add(time.Minute), Unverified, "OnDelete"},
		{"statefulset timeout", statefulSet(func(s *appsv1.StatefulSet) { s.Status.UpdateRevision = "r3" }), nil, t0.Add(time.Hour), Failed, didNotFinish},
		// DaemonSet
		{"statefulset partition is unverified", statefulSet(func(s *appsv1.StatefulSet) {
			s.Spec.UpdateStrategy.RollingUpdate = &appsv1.RollingUpdateStatefulSetStrategy{Partition: i32(1)}
		}), nil, t0.Add(time.Minute), Unverified, "partition"},
		{"statefulset partition 0 is checked", statefulSet(func(s *appsv1.StatefulSet) {
			s.Spec.UpdateStrategy.RollingUpdate = &appsv1.RollingUpdateStatefulSetStrategy{Partition: i32(0)}
		}), nil, t0.Add(time.Minute), Healthy, ""},
		{"daemonset OnDelete is unverified", daemonSet(func(d *appsv1.DaemonSet) {
			d.Spec.UpdateStrategy.Type = appsv1.OnDeleteDaemonSetStrategyType
		}), nil, t0.Add(time.Minute), Unverified, "OnDelete"},
		{"daemonset with no desired pods is unverified", daemonSet(func(d *appsv1.DaemonSet) {
			d.Status = appsv1.DaemonSetStatus{ObservedGeneration: 2}
		}), nil, t0.Add(time.Minute), Unverified, "no pods"},
		{"daemonset healthy", daemonSet(nil), nil, t0.Add(time.Minute), Healthy, ""},
		{"daemonset not all updated", daemonSet(func(d *appsv1.DaemonSet) { d.Status.UpdatedNumberScheduled = 2 }), nil, t0.Add(time.Minute), Progressing, ""},
		{"daemonset not all available", daemonSet(func(d *appsv1.DaemonSet) { d.Status.NumberAvailable = 2 }), nil, t0.Add(time.Minute), Progressing, ""},
		{"daemonset timeout", daemonSet(func(d *appsv1.DaemonSet) { d.Status.NumberAvailable = 2 }), nil, t0.Add(time.Hour), Failed, didNotFinish},
		// CronJob
		{"cronjob is always unverified", &batchv1.CronJob{}, nil, t0.Add(time.Hour), Unverified, "next run"},
		// Pod failures, each reason
		{"CreateContainerConfigError", deployment(func(d *appsv1.Deployment) { d.Status.UpdatedReplicas = 1 }), []corev1.Pod{newPod("p", newer, waiting("CreateContainerConfigError"))}, t0.Add(time.Minute), Failed, "CreateContainerConfigError"},
		{"CreateContainerError", deployment(nil), []corev1.Pod{newPod("p", newer, waiting("CreateContainerError"))}, t0.Add(time.Minute), Failed, "CreateContainerError"},
		{"RunContainerError", daemonSet(nil), []corev1.Pod{newPod("p", newer, waiting("RunContainerError"))}, t0.Add(time.Minute), Failed, "RunContainerError"},
		{crashLoop, statefulSet(nil), []corev1.Pod{newPod("p", newer, waiting(crashLoop))}, t0.Add(time.Minute), Failed, crashLoop},
		{"OOMKilled as last termination", deployment(nil), []corev1.Pod{newPod("p", newer, oomLast)}, t0.Add(time.Minute), Failed, oomKilled},
		{"OOMKilled init container", deployment(nil), []corev1.Pod{newPod("p", newer, func(p *corev1.Pod) {
			p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "i", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: oomKilled}}}}
		})}, t0.Add(time.Minute), Failed, oomKilled},
		{"harmless waiting reason is not a failure", deployment(func(d *appsv1.Deployment) { d.Status.UpdatedReplicas = 1 }), []corev1.Pod{newPod("p", newer, waiting("ContainerCreating"))}, t0.Add(time.Minute), Progressing, ""},
		// Unschedulable pods: a grace period for a cluster autoscaler, then fail
		{"unschedulable for 59s is still progressing", deployment(func(d *appsv1.Deployment) { d.Status.UpdatedReplicas = 1 }), []corev1.Pod{newPod("p", newer, unschedulable(t0))}, t0.Add(59 * time.Second), Progressing, ""},
		{"unschedulable for 61s fails", deployment(func(d *appsv1.Deployment) { d.Status.UpdatedReplicas = 1 }), []corev1.Pod{newPod("p", newer, unschedulable(t0))}, t0.Add(61 * time.Second), Failed, "Unschedulable: 0/2 nodes are available"},
		{"old unschedulable pod is ignored", deployment(nil), []corev1.Pod{newPod("p", older, unschedulable(older))}, t0.Add(time.Minute), Healthy, ""},
		// Old pods are ignored
		{"old pod with CrashLoopBackOff", deployment(nil), []corev1.Pod{newPod("p", older, waiting(crashLoop))}, t0.Add(time.Minute), Healthy, ""},
		{"old pod with OOMKilled", deployment(nil), []corev1.Pod{newPod("p", older, oomLast)}, t0.Add(time.Minute), Healthy, ""},
		{"pod made in the same second as the patch counts", deployment(nil), []corev1.Pod{newPod("p", t0, waiting(crashLoop))}, t0.Add(time.Minute), Failed, crashLoop},
		{"unverified wins over pod failure", deployment(func(d *appsv1.Deployment) { d.Spec.Paused = true }), []corev1.Pod{newPod("p", newer, waiting(crashLoop))}, t0.Add(time.Minute), Unverified, "paused"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// appliedAt has sub-second precision; pods use whole seconds.
			got, err := CheckHealth(c.obj, c.pods, t0.Add(300*time.Millisecond), c.now, timeout)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != c.want || !strings.Contains(got.Reason, c.reason) {
				t.Errorf("got %+v, want state %s with reason containing %q", got, c.want, c.reason)
			}
		})
	}
}

func TestCheckHealthRejectsUnknownType(t *testing.T) {
	if _, err := CheckHealth(&corev1.Pod{}, nil, t0, t0, timeout); err == nil {
		t.Error("want an error for a Pod")
	}
}

func revPod(name, rev string, ready corev1.ConditionStatus) corev1.Pod {
	return newPod(name, t0, func(p *corev1.Pod) {
		p.Labels = map[string]string{appsv1.ControllerRevisionHashLabelKey: rev}
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: ready}}
	})
}

func TestStuckPods(t *testing.T) {
	pods := []corev1.Pod{
		revPod("web-0", "r2", corev1.ConditionTrue),  // old revision, ready
		revPod("web-1", "r3", corev1.ConditionFalse), // bad revision, not ready: delete
		revPod("web-2", "r3", corev1.ConditionTrue),  // bad revision but ready: keep
		revPod("web-3", "r2", corev1.ConditionFalse), // old revision, not ready: not ours to delete
		newPod("web-4", t0, func(p *corev1.Pod) { p.Labels = map[string]string{appsv1.ControllerRevisionHashLabelKey: "r3"} }), // no Ready condition yet
	}
	got := StuckPods(pods, "r3")
	if len(got) != 2 || got[0].Name != "web-1" || got[1].Name != "web-4" {
		t.Errorf("stuck pods = %v, want web-1 and web-4", got)
	}
	if got := StuckPods(pods, ""); len(got) != 0 {
		t.Errorf("empty revision, but got %v", got)
	}
	if got := StuckPods(pods, "r9"); len(got) != 0 {
		t.Errorf("unknown revision, but got %v", got)
	}
}
