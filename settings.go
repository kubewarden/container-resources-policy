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

// validateOrder validates ordering: a <= b
func validateOrder(a, b resource.Quantity, aName, bName string) error {
	if !a.IsZero() && !b.IsZero() && a.Cmp(b) > 0 {
		return fmt.Errorf("%s: %s cannot be greater than %s: %s", aName, a.String(), bName, b.String())
	}
	return nil
}

func (r *ResourceConfiguration) valid() error {
	if r.allValuesAreZero() && !r.IgnoreValues {
		return AllValuesAreZeroError{}
	}

	// Core chain: minRequest <= defaultRequest <= maxRequest <= minLimit <= defaultLimit <= maxLimit
	// This enforces the constraint: limit >= request for all combinations
	// The chain ensures that any limit is always >= any request
	// Validate max limit relationships
	if err := validateOrder(r.DefaultLimit, r.MaxLimit, "default limit", "max limit"); err != nil {
		return err
	}
	if err := validateOrder(r.MinLimit, r.MaxLimit, "min limit", "max limit"); err != nil {
		return err
	}
	if err := validateOrder(r.MaxRequest, r.MaxLimit, "max request", "max limit"); err != nil {
		return err
	}
	if err := validateOrder(r.DefaultRequest, r.MaxLimit, "default request", "max limit"); err != nil {
		return err
	}
	if err := validateOrder(r.MinRequest, r.MaxLimit, "min request", "max limit"); err != nil {
		return err
	}

	// Validate default limit relationships
	if err := validateOrder(r.MinLimit, r.DefaultLimit, "min limit", "default limit"); err != nil {
		return err
	}
	if err := validateOrder(r.MaxRequest, r.DefaultLimit, "max request", "default limit"); err != nil {
		return err
	}
	if err := validateOrder(r.DefaultRequest, r.DefaultLimit, "default request", "default limit"); err != nil {
		return err
	}
	if err := validateOrder(r.MinRequest, r.DefaultLimit, "min request", "default limit"); err != nil {
		return err
	}

	// Validate min limit relationships
	if err := validateOrder(r.MaxRequest, r.MinLimit, "max request", "min limit"); err != nil {
		return err
	}
	if err := validateOrder(r.DefaultRequest, r.MinLimit, "default request", "min limit"); err != nil {
		return err
	}
	if err := validateOrder(r.MinRequest, r.MinLimit, "min request", "min limit"); err != nil {
		return err
	}

	// Validate max request relationships
	if err := validateOrder(r.DefaultRequest, r.MaxRequest, "default request", "max request"); err != nil {
		return err
	}
	if err := validateOrder(r.MinRequest, r.MaxRequest, "min request", "max request"); err != nil {
		return err
	}

	// Validate default request relationships
	if err := validateOrder(r.MinRequest, r.DefaultRequest, "min request", "default request"); err != nil {
		return err
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
