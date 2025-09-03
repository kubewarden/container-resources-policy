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
	MaxLimit       resource.Quantity `json:"maxLimit"`
	MinRequest     resource.Quantity `json:"minRequest"`
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

	if !r.MaxLimit.IsZero() {
		if r.MaxLimit.Cmp(r.DefaultLimit) < 0 ||
			r.MaxLimit.Cmp(r.DefaultRequest) < 0 {
			return fmt.Errorf("default values cannot be greater than the max limit")
		}
	}

	if !r.MinRequest.IsZero() {
		if r.MinRequest.Cmp(r.DefaultLimit) > 0 ||
			r.MinRequest.Cmp(r.DefaultRequest) > 0 {
			return fmt.Errorf("default values cannot be smaller than the min request")
		}
	}

	return nil
}

func (r *ResourceConfiguration) allValuesAreZero() bool {
	return r.MaxLimit.IsZero() && r.DefaultLimit.IsZero() && r.DefaultRequest.IsZero() && r.MinRequest.IsZero()
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
