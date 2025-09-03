package main

import (
	"encoding/json"
	"errors"
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
	if missingResourceQuantity(container.Resources.Requests, resourceName) &&
		!resourceConfig.DefaultRequest.IsZero() {
		newRequest := api_resource.Quantity(resourceConfig.DefaultRequest.String())
		container.Resources.Requests[resourceName] = &newRequest
		return true
	}
	return false
}

func validateContainerCheckPresenceLimits(container *corev1.Container, settings *Settings) error {
	if container.Resources.Limits == nil && settings.shouldIgnoreCpuValues() && settings.shouldIgnoreMemoryValues() {
		return fmt.Errorf("container does not have any resource limits")
	}

	if settings.shouldIgnoreCpuValues() && missingResourceQuantity(container.Resources.Limits, "cpu") {
		return fmt.Errorf("container does not have a cpu limit")
	}

	if settings.shouldIgnoreMemoryValues() && missingResourceQuantity(container.Resources.Limits, "memory") {
		return fmt.Errorf("container does not have a memory limit")
	}

	return nil
}

func validateContainerCheckPresenceRequests(container *corev1.Container, settings *Settings) error {
	if container.Resources.Requests == nil && settings.shouldIgnoreCpuValues() && settings.shouldIgnoreMemoryValues() {
		return fmt.Errorf("container does not have any resource requests")
	}

	_, found := container.Resources.Requests["cpu"]
	if !found && settings.shouldIgnoreCpuValues() {
		return fmt.Errorf("container does not have a cpu request")
	}

	_, found = container.Resources.Requests["memory"]
	if !found && settings.shouldIgnoreMemoryValues() {
		return fmt.Errorf("container does not have a memory request")
	}

	return nil
}

// validateContainerCheckPresence checks for the presence of the
// limits/requests (not their values) if settings.IgnoreValues is true.
// Returns an error if the limits/requests are not set and IgnoreValues is set
// to true, nil otherwise.
func validateContainerCheckPresence(container *corev1.Container, settings *Settings) error {
	if container.Resources == nil && (settings.shouldIgnoreCpuValues() || settings.shouldIgnoreMemoryValues()) {
		missing := fmt.Sprintf("required Cpu:%t, Memory:%t", settings.shouldIgnoreCpuValues(), settings.shouldIgnoreMemoryValues())
		return fmt.Errorf("container does not have any resource limits or requests: %s", missing)
	}
	if err := validateContainerCheckPresenceLimits(container, settings); err != nil {
		return err
	}
	if err := validateContainerCheckPresenceRequests(container, settings); err != nil {
		return err
	}
	return nil
}

// validateAndAdjustContainerResourceRequests mutates the container to add the
// default request values.
//
// When the CPU/Memory request is specified: no action or check is done against it.
// When the CPU/Memory request is not specified: the policy mutates the
// container and adds the `defaultRequest` value. The policy does
// not check the consistency of the applied value.
//
// Returns `true` when the container has been mutated
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

// Ensure that the limit is greater than or equal to the request
func isResourceLimitGreaterThanRequest(container *corev1.Container, resourceName string) error {
	if !missingResourceQuantity(container.Resources.Requests, resourceName) && !missingResourceQuantity(container.Resources.Limits, resourceName) {
		resourceStr := container.Resources.Limits[resourceName]
		resourceLimit, err := resource.ParseQuantity(string(*resourceStr))
		if err != nil {
			return errors.Join(fmt.Errorf("invalid %s limit", resourceName), err)
		}
		resourceStr = container.Resources.Requests[resourceName]
		resourceRequest, err := resource.ParseQuantity(string(*resourceStr))
		if err != nil {
			return errors.Join(fmt.Errorf("invalid %s request", resourceName), err)
		}
		if resourceLimit.Cmp(resourceRequest) < 0 {
			return fmt.Errorf("%s limit '%s' is less than the requested '%s' value. Please, change the resource configuration or change the policy settings to accommodate the requested value", resourceName, resourceLimit.String(), resourceRequest.String())
		}
	}
	return nil
}

// validateAndAdjustContainerMaxLimitMinRequest validates the container against the
// passed resourceConfig and mutates it if the validation didn't pass.
//
// When the CPU/Memory limit is not specified: the container is mutated to use
// the `defaultLimit`.
//
// When the CPU/Memory limit is specified: the request is accepted if the limit
// defined by the container is less than or equal to the `maxLimit`
// and more than or equal to the `minRequest`,
// or IgnoreValues is true. Otherwise the request is rejected.
//
// Returns true when it mutates the container.
func validateAndAdjustContainerMaxLimitMinRequest(container *corev1.Container, resourceName string, resourceConfig *ResourceConfiguration) (bool, error) {
	if missingResourceQuantity(container.Resources.Limits, resourceName) {
		if !resourceConfig.DefaultLimit.IsZero() {
			// if the container doesn't have a limit, and the settings have a default limit,
			// mutate and add the default limit
			newLimit := api_resource.Quantity(resourceConfig.DefaultLimit.String())
			container.Resources.Limits[resourceName] = &newLimit
			return true, nil
		}
	} else { // the container has a limit
		if !resourceConfig.MaxLimit.IsZero() {
			// the settings have a maxLimit, check that the container limit is <= maxLimit
			resourceLimitStr := container.Resources.Limits[resourceName]
			resourceLimit, err := resource.ParseQuantity(string(*resourceLimitStr))
			if err != nil {
				return false, fmt.Errorf("invalid %s limit", resourceName)
			}
			if resourceLimit.Cmp(resourceConfig.MaxLimit) > 0 {
				return false, fmt.Errorf("%s limit '%s' exceeds the max allowed value '%s'", resourceName, resourceLimit.String(), resourceConfig.MaxLimit.String())
			}
		}
	}

	if !missingResourceQuantity(container.Resources.Requests, resourceName) {
		if !resourceConfig.MinRequest.IsZero() {
			// the container has a request,
			// and the settings have a minRequest, check that the container request is >= minRequest
			resourceRequestStr := container.Resources.Requests[resourceName]
			resourceRequest, err := resource.ParseQuantity(string(*resourceRequestStr))
			if err != nil {
				return false, fmt.Errorf("invalid %s request", resourceName)
			}
			if resourceRequest.Cmp(resourceConfig.MinRequest) < 0 {
				return false, fmt.Errorf("%s request '%s' doesn't reach the min allowed value '%s'", resourceName, resourceRequest.String(), resourceConfig.MinRequest.String())
			}
		}
	}

	return false, nil
}

// validateAndAdjustContainerConstraints validates the container for maxLimit,
// minRequest, and mutates it when it doesn't pass validation.
//
// When the CPU/Memory limit is specified: the request is accepted if the limit
// defined by the container is less than or equal to the `maxLimit`
// and more than or equal to the `minRequest`,
// or IgnoreValues is true. Otherwise the request is rejected.
//
// When the CPU/Memory limit is not specified: the container is mutated to use
// the `defaultLimit`.
//
// Return `true` when the container has been mutated.
func validateAndAdjustContainerConstraints(container *corev1.Container, settings *Settings) (bool, error) {
	mutated := false
	if !settings.shouldIgnoreMemoryValues() && settings.Memory != nil {
		var err error
		mutated, err = validateAndAdjustContainerMaxLimitMinRequest(container, "memory", settings.Memory)
		if err != nil {
			return false, err
		}
	}

	if !settings.shouldIgnoreCpuValues() && settings.Cpu != nil {
		cpuMutation, err := validateAndAdjustContainerMaxLimitMinRequest(container, "cpu", settings.Cpu)
		if err != nil {
			return false, err
		}
		mutated = mutated || cpuMutation
	}
	return mutated, nil
}

// validateAndAdjustContainer validates the container against the settings, and
// returns true if the passed container has been mutated or an error if the
// validation fails.
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

	limitsMutation, err := validateAndAdjustContainerConstraints(container, settings)
	if err != nil {
		return false, err
	}
	requestsMutation := validateAndAdjustContainerResourceRequests(container, settings)

	if limitsMutation || requestsMutation {
		// If the container has been mutated with the default values, we need to
		// check that the limit is greater than the request for both CPU and
		// Memory.
		// If the limit is less than the request, we reject the request. Because
		// the user need to adjust the resource or change the policy configuration.
		// Otherwise, Kubernetes will not accept the resource mutated by the
		// policy.
		errorMsg := "There is an issue after resource limits mutation"
		if requestsMutation {
			errorMsg = "There is an issue after resource requests mutation"
		}
		if err := isResourceLimitGreaterThanRequest(container, "memory"); err != nil {
			return false, errors.Join(errors.New(errorMsg), err)
		}
		if err := isResourceLimitGreaterThanRequest(container, "cpu"); err != nil {
			return false, errors.Join(errors.New(errorMsg), err)
		}
	}
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
		if err := validateContainerCheckPresence(container, settings); err != nil {
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
	if err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(400))
	}

	mutatePod, errValidate := validatePodSpec(&podSpec, &settings)
	if errValidate != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(errValidate.Error()),
			kubewarden.Code(400))
	}
	if mutatePod {
		return kubewarden.MutatePodSpecFromRequest(validationRequest, podSpec)
	}

	return kubewarden.AcceptRequest()
}
