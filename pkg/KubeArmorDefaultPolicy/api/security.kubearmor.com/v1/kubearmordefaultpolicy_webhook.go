// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package v1

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var kubearmordefaultpolicylog = logf.Log.WithName("kubearmordefaultpolicy-resource")
var c client.Client

func (r *KubeArmorDefaultPolicy) SetupWebhookWithManager(mgr ctrl.Manager) error {
	c = mgr.GetClient()

	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

//+kubebuilder:webhook:path=/validate-security-kubearmor-com-v1-kubearmordefaultpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=security.kubearmor.com,resources=kubearmordefaultpolicies,verbs=create;update,versions=v1,name=vkubearmordefaultpolicy.kb.io,admissionReviewVersions=v1

var _ webhook.Validator = &KubeArmorDefaultPolicy{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *KubeArmorDefaultPolicy) ValidateCreate() error {
	kubearmordefaultpolicylog.Info("validate create", "name", r.Name)

	policyList := KubeArmorDefaultPolicyList{}
	if err := c.List(context.Background(), &policyList, client.InNamespace(r.Namespace)); err == nil {
		for _, p := range policyList.Items {
			if p.Name != r.Name {
				if p.Spec.File != "" && r.Spec.File != "" {
					return fmt.Errorf("file Default Posture already set in %s", p.Name)
				}
				if p.Spec.Network != "" && r.Spec.Network != "" {
					return fmt.Errorf("network Default Posture already set in %s", p.Name)
				}
				if p.Spec.Capabilities != "" && r.Spec.Capabilities != "" {
					return fmt.Errorf("capabilities Default Posture already set in %s", p.Name)
				}
			}
		}
	}

	return nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *KubeArmorDefaultPolicy) ValidateUpdate(old runtime.Object) error {
	kubearmordefaultpolicylog.Info("validate update", "name", r.Name)

	policyList := KubeArmorDefaultPolicyList{}
	if err := c.List(context.Background(), &policyList, client.InNamespace(r.Namespace)); err == nil {
		for _, p := range policyList.Items {
			if p.Name != r.Name {
				if p.Spec.File != "" && r.Spec.File != "" {
					return fmt.Errorf("file Default Posture already set in %s", p.Name)
				}
				if p.Spec.Network != "" && r.Spec.Network != "" {
					return fmt.Errorf("network Default Posture already set in %s", p.Name)
				}
				if p.Spec.Capabilities != "" && r.Spec.Capabilities != "" {
					return fmt.Errorf("capabilities Default Posture already set in %s", p.Name)
				}
			}
		}
	}

	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *KubeArmorDefaultPolicy) ValidateDelete() error {
	kubearmordefaultpolicylog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil
}
