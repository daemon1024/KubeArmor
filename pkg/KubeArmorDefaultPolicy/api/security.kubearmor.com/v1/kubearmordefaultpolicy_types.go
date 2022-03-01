// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:validation:Enum=Audit;Block
type ActionType string

// KubeArmorDefaultPolicySpec defines the desired state of KubeArmorDefaultPolicy
type KubeArmorDefaultPolicySpec struct {
	File         ActionType `json:"file,omitempty"`
	Network      ActionType `json:"network,omitempty"`
	Capabilities ActionType `json:"capabilties,omitempty"`
}

// KubeArmorDefaultPolicyStatus defines the observed state of KubeArmorDefaultPolicy
type KubeArmorDefaultPolicyStatus struct {
	PolicyStatus string `json:"status,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// KubeArmorDefaultPolicy is the Schema for the kubearmordefaultpolicies API
type KubeArmorDefaultPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubeArmorDefaultPolicySpec   `json:"spec,omitempty"`
	Status KubeArmorDefaultPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// KubeArmorDefaultPolicyList contains a list of KubeArmorDefaultPolicy
type KubeArmorDefaultPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubeArmorDefaultPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(addKnownTypes)
}
