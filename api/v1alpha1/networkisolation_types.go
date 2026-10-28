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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// The "two groups must differ" rule compares namespaces, matchLabels and matchExpressions
// one by one. CEL can't compare the two groups as whole objects, because their schemas
// count as different types. The shape of the rule keeps it inside the API server's CEL
// cost budget. matchExpressions must be in the same order to count as equal; the
// controller's overlap check catches the rest at runtime.

// NetworkIsolationSpec says which two groups of pods must not talk to each other.
// It can be edited while isolation is on: new policies are applied before old ones are removed.
type NetworkIsolationSpec struct {
	// reason is free text for the audit trail, such as an incident number.
	// +optional
	// +kubebuilder:validation:MaxLength=256
	Reason string `json:"reason,omitempty"`

	// between holds the two groups of pods that must not talk to each other.
	// Traffic is blocked both ways; all other traffic keeps working.
	// +required
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=2
	// +kubebuilder:validation:MaxItems=2
	// +kubebuilder:validation:XValidation:rule="self[0].namespaces != self[1].namespaces || has(self[0].podSelector.matchLabels) != has(self[1].podSelector.matchLabels) || (has(self[0].podSelector.matchLabels) && self[0].podSelector.matchLabels != self[1].podSelector.matchLabels) || has(self[0].podSelector.matchExpressions) != has(self[1].podSelector.matchExpressions) || (has(self[0].podSelector.matchExpressions) && self[0].podSelector.matchExpressions.map(e, [e.key, e.operator] + (has(e.values) ? e.values : [])) != self[1].podSelector.matchExpressions.map(e, [e.key, e.operator] + (has(e.values) ? e.values : [])))",message="between: the two groups must differ"
	Between []PodGroup `json:"between"`
}

// PodGroup is the set of pods that match podSelector in any of the namespaces.
type PodGroup struct {
	// name is a short name for this group. Status, events and the NetworkPolicy names use it.
	// +required
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// namespaces lists 1 to 10 namespaces. Names starting with "kube-" are not allowed.
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:XValidation:rule="self.all(n, !n.startsWith('kube-'))",message="namespaces must not start with kube-"
	Namespaces []string `json:"namespaces"`

	// podSelector picks pods in those namespaces. Empty means every pod.
	// +optional
	// +kubebuilder:default={}
	// +kubebuilder:validation:XValidation:rule="!has(self.matchExpressions) || self.matchExpressions.all(e, e.operator in ['In','NotIn','Exists','DoesNotExist'])",message="podSelector: operator must be In, NotIn, Exists or DoesNotExist"
	// +kubebuilder:validation:XValidation:rule="!has(self.matchExpressions) || self.matchExpressions.all(e, (e.operator in ['In','NotIn']) ? (has(e.values) && size(e.values) > 0) : (!has(e.values) || size(e.values) == 0))",message="podSelector: In and NotIn need at least one value; Exists and DoesNotExist must have none"
	PodSelector metav1.LabelSelector `json:"podSelector,omitzero"`
}

// Mechanism is the NetworkPolicy that blocks one direction of traffic.
// +kubebuilder:validation:Enum=IngressPolicy;EgressPolicy
type Mechanism string

const (
	// MechanismIngressPolicy is an ingress policy on the receiving group's pods.
	MechanismIngressPolicy Mechanism = "IngressPolicy"
	// MechanismEgressPolicy is an egress policy on the sending group's pods.
	MechanismEgressPolicy Mechanism = "EgressPolicy"
)

// Traffic reports whether traffic from one group to the other is blocked.
type Traffic struct {
	// from is the name of the sending group.
	From string `json:"from"`

	// to is the name of the receiving group.
	To string `json:"to"`

	// blocked is true when NetSec blocks this direction.
	Blocked bool `json:"blocked"`

	// blockedBy says which NetworkPolicy blocks this direction. It is set only when blocked.
	// IngressPolicy: a policy on the receiving group's pods.
	// EgressPolicy: a policy on the sending group's pods.
	// +optional
	BlockedBy Mechanism `json:"blockedBy,omitempty"`

	// policies lists the NetworkPolicies that block it, as namespace/name.
	// +optional
	// +listType=atomic
	Policies []string `json:"policies,omitempty"`

	// message explains why this direction is not blocked. It is set only when not blocked.
	// +optional
	Message string `json:"message,omitempty"`
}

// GroupPods counts the pods in one group.
type GroupPods struct {
	// group is the group's name.
	Group string `json:"group"`

	// count is the number of pods that match the group right now.
	Count int32 `json:"count"`
}

// NetworkIsolationStatus defines the observed state of NetworkIsolation.
type NetworkIsolationStatus struct {
	// observedGeneration is the spec generation this status describes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// summary is a one-line answer to "is it isolated?".
	// +optional
	Summary string `json:"summary,omitempty"`

	// conditions are Ready and Degraded.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// traffic says, for both directions, whether traffic is blocked and how.
	// +optional
	// +listType=atomic
	Traffic []Traffic `json:"traffic,omitempty"`

	// pods counts the pods in each group.
	// +optional
	// +listType=map
	// +listMapKey=group
	Pods []GroupPods `json:"pods,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=iso
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Isolated",type=string,JSONPath=`.status.summary`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// NetworkIsolation blocks traffic both ways between two groups of pods.
// Create it to turn isolation on; delete it to turn isolation off.
type NetworkIsolation struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of NetworkIsolation
	// +required
	Spec NetworkIsolationSpec `json:"spec"`

	// status defines the observed state of NetworkIsolation
	// +optional
	Status NetworkIsolationStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// NetworkIsolationList contains a list of NetworkIsolation
type NetworkIsolationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []NetworkIsolation `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &NetworkIsolation{}, &NetworkIsolationList{})
		return nil
	})
}
