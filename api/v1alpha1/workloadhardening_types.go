/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// WorkloadKind is a workload type that hardening can patch.
// +kubebuilder:validation:Enum=Deployment;StatefulSet;DaemonSet;CronJob
type WorkloadKind string

const (
	KindDeployment  WorkloadKind = "Deployment"
	KindStatefulSet WorkloadKind = "StatefulSet"
	KindDaemonSet   WorkloadKind = "DaemonSet"
	KindCronJob     WorkloadKind = "CronJob"
)

// HardeningAction is what the operator should do with the plan.
// +kubebuilder:validation:Enum=Plan;Apply;Undo
type HardeningAction string

const (
	// ActionPlan only computes the plan. Nothing is changed.
	ActionPlan HardeningAction = "Plan"
	// ActionApply rolls out the approved plan.
	ActionApply HardeningAction = "Apply"
	// ActionUndo removes the fields this object set.
	ActionUndo HardeningAction = "Undo"
)

// WorkloadHardeningSpec says which workloads to harden and how.
// +kubebuilder:validation:XValidation:rule="self.action != 'Apply' || (has(self.approvedPlanHash) && size(self.approvedPlanHash) > 0)",message="approvedPlanHash is required when action is Apply; copy it from status.plan.hash"
type WorkloadHardeningSpec struct {
	// namespaces lists 1 to 20 namespaces to harden. Names starting with "kube-" are not allowed.
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=20
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:XValidation:rule="self.all(n, !n.startsWith('kube-'))",message="namespaces must not start with kube-"
	Namespaces []string `json:"namespaces"`

	// workloadSelector picks workloads by the workload's own labels (not the pod template's).
	// Empty means all.
	// +optional
	// +kubebuilder:validation:XValidation:rule="!has(self.matchExpressions) || self.matchExpressions.all(e, e.operator in ['In','NotIn','Exists','DoesNotExist'])",message="workloadSelector: operator must be In, NotIn, Exists or DoesNotExist"
	// +kubebuilder:validation:XValidation:rule="!has(self.matchExpressions) || self.matchExpressions.all(e, (e.operator in ['In','NotIn']) ? (has(e.values) && size(e.values) > 0) : (!has(e.values) || size(e.values) == 0))",message="workloadSelector: In and NotIn need at least one value; Exists and DoesNotExist must have none"
	WorkloadSelector metav1.LabelSelector `json:"workloadSelector,omitzero"`

	// workloadKinds lists the workload types to patch. The default is all four.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=4
	// +kubebuilder:default={"Deployment","StatefulSet","DaemonSet","CronJob"}
	WorkloadKinds []WorkloadKind `json:"workloadKinds,omitempty"`

	// strictSecurity turns on extra settings that can stop some images from starting.
	// The safe ones (seccomp RuntimeDefault, no privilege escalation) are always applied.
	// +optional
	// +kubebuilder:default={}
	StrictSecurity StrictSecurity `json:"strictSecurity,omitzero"`

	// The default is spelled out in full because the API server checks it against
	// the limits >= requests rule before the nested defaults fill in.

	// defaultResources are set only on containers that have none, unless a
	// namespace LimitRange sets a default for that resource.
	// Existing values are never lowered.
	// +optional
	// +kubebuilder:default={"enabled":true,"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"memory":"512Mi"}}
	DefaultResources DefaultResources `json:"defaultResources,omitzero"`

	// action is Plan, Apply or Undo.
	// +optional
	// +kubebuilder:default=Plan
	Action HardeningAction `json:"action,omitempty"`

	// approvedPlanHash: copy status.plan.hash here, with action: Apply, to approve exactly that plan.
	// +optional
	// +kubebuilder:validation:Pattern=`^([0-9a-f]{16})?$`
	ApprovedPlanHash string `json:"approvedPlanHash,omitempty"`

	// maxConcurrentRollouts is how many workloads roll out at once (1 to 10).
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	MaxConcurrentRollouts int32 `json:"maxConcurrentRollouts,omitempty"`

	// rolloutTimeout is how long one workload may take to become healthy (1m to 30m). The limit is per workload.
	// +optional
	// +kubebuilder:default="5m"
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1m') && duration(self) <= duration('30m')",message="rolloutTimeout must be between 1m and 30m"
	RolloutTimeout metav1.Duration `json:"rolloutTimeout,omitzero"`
}

// StrictSecurity turns on the settings that can break some images.
type StrictSecurity struct {
	// runAsNonRoot sets runAsNonRoot: true on the pod.
	// +optional
	RunAsNonRoot bool `json:"runAsNonRoot,omitempty"`

	// dropAllCapabilities sets capabilities.drop: [ALL] on each container.
	// +optional
	DropAllCapabilities bool `json:"dropAllCapabilities,omitempty"`

	// readOnlyRootFilesystem sets readOnlyRootFilesystem: true on each container.
	// +optional
	ReadOnlyRootFilesystem bool `json:"readOnlyRootFilesystem,omitempty"`
}

// DefaultResources are the values set on containers that have none.
// +kubebuilder:validation:XValidation:rule="quantity(string(self.limits.memory)).compareTo(quantity(string(self.requests.memory))) >= 0",message="limits.memory must be at least requests.memory"
type DefaultResources struct {
	// enabled turns resource defaults on or off.
	// +optional
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty"`

	// requests are the default requests.
	// +optional
	// +kubebuilder:default={}
	Requests ResourceRequests `json:"requests,omitzero"`

	// limits are the default limits. A CPU limit is never set.
	// +optional
	// +kubebuilder:default={}
	Limits ResourceLimits `json:"limits,omitzero"`
}

// ResourceRequests are the default CPU and memory requests.
type ResourceRequests struct {
	// cpu must be more than 0 and at most 2.
	// +optional
	// +kubebuilder:default="100m"
	// +kubebuilder:validation:XValidation:rule="quantity(string(self)).isGreaterThan(quantity('0')) && quantity(string(self)).compareTo(quantity('2')) <= 0",message="requests.cpu must be more than 0 and at most 2"
	CPU resource.Quantity `json:"cpu,omitzero"`

	// memory must be more than 0 and at most 4Gi.
	// +optional
	// +kubebuilder:default="128Mi"
	// +kubebuilder:validation:XValidation:rule="quantity(string(self)).isGreaterThan(quantity('0')) && quantity(string(self)).compareTo(quantity('4Gi')) <= 0",message="requests.memory must be more than 0 and at most 4Gi"
	Memory resource.Quantity `json:"memory,omitzero"`
}

// ResourceLimits are the default limits.
type ResourceLimits struct {
	// memory must be at least requests.memory and at most 8Gi.
	// +optional
	// +kubebuilder:default="512Mi"
	// +kubebuilder:validation:XValidation:rule="quantity(string(self)).compareTo(quantity('8Gi')) <= 0",message="limits.memory must be at most 8Gi"
	Memory resource.Quantity `json:"memory,omitzero"`
}

// HardeningPhase is where a WorkloadHardening is in its life.
// +kubebuilder:validation:Enum=Planning;Planned;Applying;Completed;Failed;Undoing;Undone
type HardeningPhase string

const (
	PhasePlanning  HardeningPhase = "Planning"
	PhasePlanned   HardeningPhase = "Planned"
	PhaseApplying  HardeningPhase = "Applying"
	PhaseCompleted HardeningPhase = "Completed"
	PhaseFailed    HardeningPhase = "Failed"
	PhaseUndoing   HardeningPhase = "Undoing"
	PhaseUndone    HardeningPhase = "Undone"
)

// WorkloadState is where one workload is in the plan.
// +kubebuilder:validation:Enum=Pending;Applying;Healthy;Unverified;Reverted;Failed;Skipped;NoChange;Undoing;Undone
type WorkloadState string

const (
	StatePending    WorkloadState = "Pending"
	StateApplying   WorkloadState = "Applying"
	StateHealthy    WorkloadState = "Healthy"
	StateUnverified WorkloadState = "Unverified"
	StateReverted   WorkloadState = "Reverted"
	StateFailed     WorkloadState = "Failed"
	StateSkipped    WorkloadState = "Skipped"
	StateNoChange   WorkloadState = "NoChange"
	StateUndoing    WorkloadState = "Undoing"
	StateUndone     WorkloadState = "Undone"
)

// PlannedWorkload is one workload in the plan.
type PlannedWorkload struct {
	// kind is the workload type.
	Kind WorkloadKind `json:"kind"`

	// namespace is the workload's namespace.
	Namespace string `json:"namespace"`

	// name is the workload's name.
	Name string `json:"name"`

	// generation is the workload's generation when it was planned, then when it was patched.
	// +optional
	Generation int64 `json:"generation,omitempty"`

	// state is where this workload is.
	State WorkloadState `json:"state"`

	// reason explains the state, for example why a workload was skipped, failed or reverted.
	// +optional
	Reason string `json:"reason,omitempty"`

	// changes lists each field to set, as "path: old → new".
	// +optional
	// +listType=atomic
	Changes []string `json:"changes,omitempty"`

	// warnings lists risks seen in this workload that NetSec will not fix.
	// They are not part of the plan hash.
	// +optional
	// +listType=atomic
	Warnings []string `json:"warnings,omitempty"`

	// appliedAt is when the patch was sent. Pods created after it are checked by the health gate.
	// +optional
	AppliedAt *metav1.Time `json:"appliedAt,omitempty"`

	// failedRevision is set only for StatefulSets.
	// The StatefulSet revision whose pods failed; NetSec deletes them after the revert.
	// +optional
	FailedRevision string `json:"failedRevision,omitempty"`
}

// HardeningPlan is the list of changes waiting for approval.
type HardeningPlan struct {
	// hash identifies this exact plan. Copy it to spec.approvedPlanHash to approve it.
	Hash string `json:"hash"`

	// workloads lists every target and what would change.
	// +optional
	// +listType=atomic
	Workloads []PlannedWorkload `json:"workloads,omitempty"`
}

// WorkloadHardeningStatus defines the observed state of WorkloadHardening.
type WorkloadHardeningStatus struct {
	// observedGeneration is the spec generation this status describes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// phase is where this object is in its life.
	// +optional
	Phase HardeningPhase `json:"phase,omitempty"`

	// summary is a one-line count of what is happening, such as "3 to change, 2 skipped".
	// +optional
	Summary string `json:"summary,omitempty"`

	// plan is the current plan.
	// +optional
	Plan *HardeningPlan `json:"plan,omitempty"`

	// conditions are Ready, Degraded, PlanStale and Refused.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=wh
// +kubebuilder:printcolumn:name="Action",type=string,JSONPath=`.spec.action`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Summary",type=string,JSONPath=`.status.summary`
// +kubebuilder:printcolumn:name="Plan",type=string,JSONPath=`.status.plan.hash`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WorkloadHardening plans, applies and undoes safe securityContext and resource
// defaults on workloads. Nothing changes until a plan is approved.
type WorkloadHardening struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of WorkloadHardening
	// +required
	Spec WorkloadHardeningSpec `json:"spec"`

	// status defines the observed state of WorkloadHardening
	// +optional
	Status WorkloadHardeningStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// WorkloadHardeningList contains a list of WorkloadHardening
type WorkloadHardeningList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []WorkloadHardening `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &WorkloadHardening{}, &WorkloadHardeningList{})
		return nil
	})
}
