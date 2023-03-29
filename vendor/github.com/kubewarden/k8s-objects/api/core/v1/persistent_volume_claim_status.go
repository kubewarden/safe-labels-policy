// Code generated by go-swagger; DO NOT EDIT.

package v1

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	apimachinery_pkg_api_resource "github.com/kubewarden/k8s-objects/apimachinery/pkg/api/resource"
)

// PersistentVolumeClaimStatus PersistentVolumeClaimStatus is the current status of a persistent volume claim.
//
// swagger:model PersistentVolumeClaimStatus
type PersistentVolumeClaimStatus struct {

	// accessModes contains the actual access modes the volume backing the PVC has. More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#access-modes-1
	AccessModes []string `json:"accessModes,omitempty"`

	// allocatedResources is the storage resource within AllocatedResources tracks the capacity allocated to a PVC. It may be larger than the actual capacity when a volume expansion operation is requested. For storage quota, the larger value from allocatedResources and PVC.spec.resources is used. If allocatedResources is not set, PVC.spec.resources alone is used for quota calculation. If a volume expansion capacity request is lowered, allocatedResources is only lowered if there are no expansion operations in progress and if the actual volume capacity is equal or lower than the requested capacity. This is an alpha field and requires enabling RecoverVolumeExpansionFailure feature.
	AllocatedResources map[string]*apimachinery_pkg_api_resource.Quantity `json:"allocatedResources,omitempty"`

	// capacity represents the actual resources of the underlying volume.
	Capacity map[string]*apimachinery_pkg_api_resource.Quantity `json:"capacity,omitempty"`

	// conditions is the current Condition of persistent volume claim. If underlying persistent volume is being resized then the Condition will be set to 'ResizeStarted'.
	Conditions []*PersistentVolumeClaimCondition `json:"conditions,omitempty"`

	// phase represents the current phase of PersistentVolumeClaim.
	//
	//
	Phase string `json:"phase,omitempty"`

	// resizeStatus stores status of resize operation. ResizeStatus is not set by default but when expansion is complete resizeStatus is set to empty string by resize controller or kubelet. This is an alpha field and requires enabling RecoverVolumeExpansionFailure feature.
	ResizeStatus string `json:"resizeStatus,omitempty"`
}
