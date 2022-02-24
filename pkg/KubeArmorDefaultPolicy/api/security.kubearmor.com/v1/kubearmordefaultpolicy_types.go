/*
Copyright 2022 KubeArmor.

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
