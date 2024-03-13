package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kubewarden/container-resources-policy/resource"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	api_resource "github.com/kubewarden/k8s-objects/apimachinery/pkg/api/resource"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

func missingResourceQuantity(resources map[string]*api_resource.Quantity, resourceName string) bool {
	resourceStr, found := resources[resourceName]
	return !found || resourceStr == nil || len(strings.TrimSpace(string(*resourceStr))) == 0
}

func adjustResourceRequest(container *corev1.Container, resourceName string, resourceConfig *ResourceConfiguration) bool {
	if missingResourceQuantity(container.Resources.Requests, resourceName) {
		if !resourceConfig.DefaultRequest.IsZero() {
			newRequest := api_resource.Quantity(resourceConfig.DefaultRequest.String())
			container.Resources.Requests[resourceName] = &newRequest
			return true
		}
	}
	return false
}

func validateContainerResourceLimits(container *corev1.Container, settings *Settings) error {
	if container.Resources.Limits == nil && settings.Cpu.IgnoreValues && settings.Memory.IgnoreValues {
		return fmt.Errorf("container does not have any resource limits")
	}

	if settings.Cpu.IgnoreValues && missingResourceQuantity(container.Resources.Limits, "cpu") {
		return fmt.Errorf("container does not have a cpu limit")
	}

	if settings.Memory.IgnoreValues && missingResourceQuantity(container.Resources.Limits, "memory") {
		return fmt.Errorf("container does not have a memory limit")
	}

	return nil
}

func validateContainerResourceRequests(container *corev1.Container, settings *Settings) error {
	if container.Resources.Requests == nil && settings.Cpu.IgnoreValues && settings.Memory.IgnoreValues {
		return fmt.Errorf("container does not have any resource requests")
	}

	_, found := container.Resources.Requests["cpu"]
	if !found && settings.Cpu.IgnoreValues {
		return fmt.Errorf("container does not have a cpu request")
	}

	_, found = container.Resources.Requests["memory"]
	if !found && settings.Memory.IgnoreValues {
		return fmt.Errorf("container does not have a memory request")
	}

	return nil
}

// If IgnoreValues is set to true, confirm that the respective limits/requests are set.
// We only check for the presence of the limits/requests, not their values.
// Returns an error if the limits/requests are not set and IgnoreValues is set to true.
func validateContainerResources(container *corev1.Container, settings *Settings) error {
	if container.Resources == nil && (settings.Cpu.IgnoreValues || settings.Memory.IgnoreValues) {
		missing := fmt.Sprintf("required Cpu:%t, Memory:%t", settings.Cpu.IgnoreValues, settings.Memory.IgnoreValues)
		return fmt.Errorf("container does not have any resource limits or requests: %s", missing)
	}
	if err := validateContainerResourceLimits(container, settings); err != nil {
		return err
	}
	if err := validateContainerResourceRequests(container, settings); err != nil {
		return err
	}
	return nil
}

// When the CPU/Memory request is specified: no action or check is done against it.
// When the CPU/Memory request is not specified: the policy mutates the container definition, the `defaultRequest` value is used. The policy does not check the consistency of the applied value.
// Return `true` when the container has been mutated
func validateAndAdjustContainerResourceRequests(container *corev1.Container, settings *Settings) bool {
	mutated := false
	if settings.Memory != nil {
		mutated = adjustResourceRequest(container, "memory", settings.Memory)
	}
	if settings.Cpu != nil {
		mutated = adjustResourceRequest(container, "cpu", settings.Cpu) || mutated
	}
	return mutated
}

// validateAndAdjustContainerResourceLimit validates the container against the passed resourceConfig // and mutates it if the validation didn't pass.
// Returns true when it mutates the container.
func validateAndAdjustContainerResourceLimit(container *corev1.Container, resourceName string, resourceConfig *ResourceConfiguration) (bool, error) {
	if missingResourceQuantity(container.Resources.Limits, resourceName) {
		if !resourceConfig.DefaultLimit.IsZero() {
			newLimit := api_resource.Quantity(resourceConfig.DefaultLimit.String())
			container.Resources.Limits[resourceName] = &newLimit
			return true, nil
		}
	} else {
		resourceStr := container.Resources.Limits[resourceName]
		resourceLimit, err := resource.ParseQuantity(string(*resourceStr))
		if err != nil {
			return false, fmt.Errorf("invalid %s limit", resourceName)
		}
		if resourceLimit.Cmp(resourceConfig.MaxLimit) > 0 {
			return false, fmt.Errorf("%s limit '%s' exceeds the max allowed value '%s'", resourceName, resourceLimit.String(), resourceConfig.MaxLimit.String())
		}
	}
	return false, nil
}

// validateAndAdjustContainerResourceLimits validates the container and mutates
// it when possible, when it doesn't pass validation.
//
// When the CPU/Memory limit is specified: the request is accepted if the limit
// defined by the container is less than or equal to the `maxLimit`, or
// IgnoreValues is true. Otherwise the request is rejected.
//
// When the CPU/Memory limit is not specified: the container is mutated to use
// the `defaultLimit`.
//
// Return `true` when the container has been mutated.
func validateAndAdjustContainerResourceLimits(container *corev1.Container, settings *Settings) (bool, error) {
	mutated := false
	if settings.Memory.IgnoreValues {
		return false, nil
	}
	if settings.Memory != nil {
		var err error
		mutated, err = validateAndAdjustContainerResourceLimit(container, "memory", settings.Memory)
		if err != nil {
			return false, err
		}
	}

	if settings.Cpu.IgnoreValues {
		return false, nil
	}
	if settings.Cpu != nil {
		cpuMutation, err := validateAndAdjustContainerResourceLimit(container, "cpu", settings.Cpu)
		if err != nil {
			return false, err
		}
		mutated = mutated || cpuMutation
	}
	return mutated, nil
}

func validateAndAdjustContainer(container *corev1.Container, settings *Settings) (bool, error) {
	if container.Resources == nil {
		container.Resources = &corev1.ResourceRequirements{
			Limits:   make(map[string]*api_resource.Quantity),
			Requests: make(map[string]*api_resource.Quantity),
		}
	}
	if container.Resources.Limits == nil {
		container.Resources.Limits = make(map[string]*api_resource.Quantity)
	}
	if container.Resources.Requests == nil {
		container.Resources.Requests = make(map[string]*api_resource.Quantity)
	}
	limitsMutation, err := validateAndAdjustContainerResourceLimits(container, settings)
	if err != nil {
		return false, err
	}
	requestsMutation := validateAndAdjustContainerResourceRequests(container, settings)
	return limitsMutation || requestsMutation, nil
}

func shouldSkipContainer(image string, ignoreImages []string) bool {
	for _, ignoreImageUri := range ignoreImages {
		if !strings.HasSuffix(ignoreImageUri, "*") {
			if image == ignoreImageUri {
				return true
			}
		} else {
			imageUriNoSuffix := strings.TrimSuffix(ignoreImageUri, "*")
			if strings.HasPrefix(image, imageUriNoSuffix) {
				return true
			}
		}
	}
	return false
}

func validatePodSpec(pod *corev1.PodSpec, settings *Settings) (bool, error) {
	mutated := false
	for _, container := range pod.Containers {
		if shouldSkipContainer(container.Image, settings.IgnoreImages) {
			continue
		}
		if err := validateContainerResources(container, settings); err != nil {
			return false, err
		}

		containerMutated, err := validateAndAdjustContainer(container, settings)
		if err != nil {
			return false, err
		}
		mutated = mutated || containerMutated
	}
	return mutated, nil
}

func validate(payload []byte) ([]byte, error) {
	// Create a ValidationRequest instance from the incoming payload
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := json.Unmarshal(payload, &validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	// Create a Settings instance from the ValidationRequest object
	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	podSpec, err := kubewarden.ExtractPodSpecFromObject(validationRequest)
	if err == nil {
		mutatePod, err := validatePodSpec(&podSpec, &settings)
		if err != nil {
			return kubewarden.RejectRequest(
				kubewarden.Message(err.Error()),
				kubewarden.Code(400))
		}
		if mutatePod {
			return kubewarden.MutatePodSpecFromRequest(validationRequest, podSpec)
		}
	} else {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(400))
	}

	return kubewarden.AcceptRequest()
}
