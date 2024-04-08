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
	DefaultRequest resource.Quantity `json:"defaultRequest"`
	DefaultLimit   resource.Quantity `json:"defaultLimit"`
	IgnoreValues   bool              `json:"ignoreValues,omitempty"`
}

type Settings struct {
	Cpu          *ResourceConfiguration `json:"cpu,omitempty"`
	Memory       *ResourceConfiguration `json:"memory,omitempty"`
	IgnoreImages []string               `json:"ignoreImages,omitempty"`
}

func (s *Settings) shouldIgnoreCpuValues() bool {
	return s.Cpu != nil && s.Cpu.IgnoreValues
}

func (s *Settings) shouldIgnoreMemoryValues() bool {
	return s.Memory != nil && s.Memory.IgnoreValues
}

func (r *ResourceConfiguration) valid() error {
	if (!r.MaxLimit.IsZero() || !r.DefaultLimit.IsZero() || !r.DefaultRequest.IsZero()) && r.IgnoreValues {
		return fmt.Errorf("ignoreValues cannot be true when any quantities are defined")
	}

	if r.IgnoreValues {
		return nil
	}

	if r.MaxLimit.IsZero() && r.DefaultLimit.IsZero() && r.DefaultRequest.IsZero() {
		return fmt.Errorf("all the quantities must be defined")
	}

	if r.MaxLimit.Cmp(r.DefaultLimit) < 0 ||
		r.MaxLimit.Cmp(r.DefaultRequest) < 0 {
		return fmt.Errorf("default values cannot be greater than the max limit")
	}

	return nil
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
