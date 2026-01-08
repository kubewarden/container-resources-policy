package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kubewarden/container-resources-policy/resource"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

type ResourceConfiguration struct {
	MinLimit       resource.Quantity `json:"minLimit"`
	MaxLimit       resource.Quantity `json:"maxLimit"`
	MinRequest     resource.Quantity `json:"minRequest"`
	MaxRequest     resource.Quantity `json:"maxRequest"`
	DefaultRequest resource.Quantity `json:"defaultRequest"`
	DefaultLimit   resource.Quantity `json:"defaultLimit"`
	IgnoreValues   bool              `json:"ignoreValues,omitempty"`
}

type Settings struct {
	Cpu          *ResourceConfiguration `json:"cpu,omitempty"`
	Memory       *ResourceConfiguration `json:"memory,omitempty"`
	IgnoreImages []string               `json:"ignoreImages,omitempty"`
}

type AllValuesAreZeroError struct{}

func (e AllValuesAreZeroError) Error() string {
	return "all the quantities must be defined"
}

func (s *Settings) shouldIgnoreCpuValues() bool {
	return s.Cpu != nil && (s.Cpu.IgnoreValues || (!s.Cpu.IgnoreValues && s.Cpu.allValuesAreZero()))
}

func (s *Settings) shouldIgnoreMemoryValues() bool {
	return s.Memory != nil && (s.Memory.IgnoreValues || (!s.Memory.IgnoreValues && s.Memory.allValuesAreZero()))
}

func (r *ResourceConfiguration) valid() error {
	if r.allValuesAreZero() && !r.IgnoreValues {
		return AllValuesAreZeroError{}
	}

	// Core chain: minRequest <= defaultRequest <= maxRequest <= minLimit <= defaultLimit <= maxLimit
	// This enforces the constraint: limit >= request for all combinations
	// The chain ensures that any limit is always >= any request

	// Validate max limit relationships
	// defaultLimit <= maxLimit
	if !r.DefaultLimit.IsZero() && !r.MaxLimit.IsZero() && r.DefaultLimit.Cmp(r.MaxLimit) > 0 {
		return fmt.Errorf("default limit: %s cannot be greater than max limit: %s", r.DefaultLimit.String(), r.MaxLimit.String())
	}
	// minLimit <= maxLimit
	if !r.MinLimit.IsZero() && !r.MaxLimit.IsZero() && r.MinLimit.Cmp(r.MaxLimit) > 0 {
		return fmt.Errorf("min limit: %s cannot be greater than max limit: %s", r.MinLimit.String(), r.MaxLimit.String())
	}
	// maxRequest <= maxLimit
	if !r.MaxRequest.IsZero() && !r.MaxLimit.IsZero() && r.MaxRequest.Cmp(r.MaxLimit) > 0 {
		return fmt.Errorf("max request: %s cannot be greater than max limit: %s", r.MaxRequest.String(), r.MaxLimit.String())
	}
	// defaultRequest <= maxLimit
	if !r.DefaultRequest.IsZero() && !r.MaxLimit.IsZero() && r.DefaultRequest.Cmp(r.MaxLimit) > 0 {
		return fmt.Errorf("default request: %s cannot be greater than max limit: %s", r.DefaultRequest.String(), r.MaxLimit.String())
	}
	// minRequest <= maxLimit
	if !r.MinRequest.IsZero() && !r.MaxLimit.IsZero() && r.MinRequest.Cmp(r.MaxLimit) > 0 {
		return fmt.Errorf("min request: %s cannot be greater than max limit: %s", r.MinRequest.String(), r.MaxLimit.String())
	}

	// Validate default limit relationships
	// minLimit <= defaultLimit
	if !r.MinLimit.IsZero() && !r.DefaultLimit.IsZero() && r.MinLimit.Cmp(r.DefaultLimit) > 0 {
		return fmt.Errorf("min limit: %s cannot be greater than default limit: %s", r.MinLimit.String(), r.DefaultLimit.String())
	}
	// maxRequest <= defaultLimit
	if !r.MaxRequest.IsZero() && !r.DefaultLimit.IsZero() && r.MaxRequest.Cmp(r.DefaultLimit) > 0 {
		return fmt.Errorf("max request: %s cannot be greater than default limit: %s", r.MaxRequest.String(), r.DefaultLimit.String())
	}
	// defaultRequest <= defaultLimit
	if !r.DefaultRequest.IsZero() && !r.DefaultLimit.IsZero() && r.DefaultRequest.Cmp(r.DefaultLimit) > 0 {
		return fmt.Errorf("default request: %s cannot be greater than default limit: %s", r.DefaultRequest.String(), r.DefaultLimit.String())
	}
	// minRequest <= defaultLimit
	if !r.MinRequest.IsZero() && !r.DefaultLimit.IsZero() && r.MinRequest.Cmp(r.DefaultLimit) > 0 {
		return fmt.Errorf("min request: %s cannot be greater than default limit: %s", r.MinRequest.String(), r.DefaultLimit.String())
	}

	// Validate min limit relationships
	// maxRequest <= minLimit
	if !r.MaxRequest.IsZero() && !r.MinLimit.IsZero() && r.MaxRequest.Cmp(r.MinLimit) > 0 {
		return fmt.Errorf("max request: %s cannot be greater than min limit: %s", r.MaxRequest.String(), r.MinLimit.String())
	}
	// defaultRequest <= minLimit
	if !r.DefaultRequest.IsZero() && !r.MinLimit.IsZero() && r.DefaultRequest.Cmp(r.MinLimit) > 0 {
		return fmt.Errorf("default request: %s cannot be greater than min limit: %s", r.DefaultRequest.String(), r.MinLimit.String())
	}
	// minRequest <= minLimit
	if !r.MinRequest.IsZero() && !r.MinLimit.IsZero() && r.MinRequest.Cmp(r.MinLimit) > 0 {
		return fmt.Errorf("min request: %s cannot be greater than min limit: %s", r.MinRequest.String(), r.MinLimit.String())
	}

	// Validate max request relationships
	// defaultRequest <= maxRequest
	if !r.DefaultRequest.IsZero() && !r.MaxRequest.IsZero() && r.DefaultRequest.Cmp(r.MaxRequest) > 0 {
		return fmt.Errorf("default request: %s cannot be greater than max request: %s", r.DefaultRequest.String(), r.MaxRequest.String())
	}
	// minRequest <= maxRequest
	if !r.MinRequest.IsZero() && !r.MaxRequest.IsZero() && r.MinRequest.Cmp(r.MaxRequest) > 0 {
		return fmt.Errorf("min request: %s cannot be greater than max request: %s", r.MinRequest.String(), r.MaxRequest.String())
	}

	// Validate default request relationships
	// minRequest <= defaultRequest
	if !r.MinRequest.IsZero() && !r.DefaultRequest.IsZero() && r.MinRequest.Cmp(r.DefaultRequest) > 0 {
		return fmt.Errorf("min request: %s cannot be greater than default request: %s", r.MinRequest.String(), r.DefaultRequest.String())
	}

	return nil
}

func (r *ResourceConfiguration) allValuesAreZero() bool {
	return r.MaxLimit.IsZero() && r.DefaultLimit.IsZero() && r.DefaultRequest.IsZero() && r.MinRequest.IsZero() && r.MinLimit.IsZero() && r.MaxRequest.IsZero()
}

func (s *Settings) Valid() error {
	if s.Cpu == nil && s.Memory == nil {
		return fmt.Errorf("no settings provided. At least one resource limit or request must be verified")
	}

	var cpuError, memoryError error
	if s.Cpu != nil {
		cpuError = s.Cpu.valid()
		if cpuError != nil {
			cpuError = errors.Join(fmt.Errorf("invalid cpu settings"), cpuError)
		}
	}
	if s.Memory != nil {
		memoryError = s.Memory.valid()
		if memoryError != nil {
			memoryError = errors.Join(fmt.Errorf("invalid memory settings"), memoryError)
		}
	}
	if cpuError != nil || memoryError != nil {
		// user want to validate only one type of resource. The other one should be ignored
		if (cpuError == nil && errors.Is(memoryError, AllValuesAreZeroError{})) || (memoryError == nil && errors.Is(cpuError, AllValuesAreZeroError{})) {
			return nil
		}
		return errors.Join(cpuError, memoryError)
	}
	return nil
}

func NewSettingsFromValidationReq(validationReq *kubewarden_protocol.ValidationRequest) (Settings, error) {
	settings := Settings{}
	err := json.Unmarshal(validationReq.Settings, &settings)
	return settings, err
}

func validateSettings(payload []byte) ([]byte, error) {
	logger.Info("validating settings")
	settings := Settings{}
	err := json.Unmarshal(payload, &settings)
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}

	err = settings.Valid()
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}
	return kubewarden.AcceptSettings()
}
