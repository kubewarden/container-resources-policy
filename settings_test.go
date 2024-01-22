package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kubewarden/container-resources-policy/resource"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

func TestParsingResourceConfiguration(t *testing.T) {
	var tests = []struct {
		name         string
		rawSettings  []byte
		errorMessage string
	}{
		{"no suffix", []byte(`{"maxLimit": "3", "defaultLimit": "2", "defaultRequest": "1"}`), ""},
		{"invalid limit suffix", []byte(`{"maxLimit": "1x", "defaultLimit": "1m", "defaultRequest": "1m"}`), "quantities must match the regular expression"},
		{"invalid request suffix", []byte(`{"maxLimit": "3m", "defaultLimit": "2m", "defaultRequest": "1x"}`), "quantities must match the regular expression"},
		{"defaults greater than max limit", []byte(`{"maxLimit": "2m", "defaultRequest": "3m", "defaultLimit": "4m"}`), "default values cannot be greater than the max limit"},
		{"valid resource configuration", []byte(`{"maxLimit": "4G", "defaultLimit": "2G", "defaultRequest": "1G"}`), ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings := &ResourceConfiguration{}
			if err := json.Unmarshal(test.rawSettings, settings); err != nil {
				if len(test.errorMessage) == 0 {
					t.Fatalf("Unexpected error: %+v", err)
				}
				if !strings.Contains(err.Error(), test.errorMessage) {
					t.Fatalf("invalid error message. Expected the string '%s' in the error. Got '%s'", test.errorMessage, err.Error())
				}
				return
			}
			err := settings.valid()
			if len(test.errorMessage) == 0 && err != nil {
				t.Fatalf("unexpected validation error: %+v", err)
			}
			if len(test.errorMessage) > 0 {
				if err == nil {
					t.Fatalf("expected error message with string '%s'. But no error has been returned", test.errorMessage)
				}
				if !strings.Contains(err.Error(), test.errorMessage) {
					t.Errorf("invalid error message. Expected the string '%s' in the error. Got '%s'", test.errorMessage, err.Error())
				}
			}
		})
	}
}

func TestParsingSettings(t *testing.T) {
	var tests = []struct {
		name         string
		rawSettings  []byte
		errorMessage string
	}{
		{"invalid settings", []byte(`{}`), "no settings provided. At least one resource limit or request must be verified"},
		{"valid settings", []byte(`{"cpu": {"maxLimit": "1m", "defaultRequest": "1m", "defaultLimit": "1m"}, "memory":{ "defaultLimit": "200M", "defaultRequest": "100M", "maxLimit": "500M"}, "ignoreImages": ["image:latest"]}`), ""},
		{"valid settings with cpu field only", []byte(`{"cpu": {"maxLimit": "1m", "defaultRequest": "1m", "defaultLimit": "1m"}}`), ""},
		{"valid settings with memory fields only", []byte(`{"memory":{ "defaultLimit": "200M", "defaultRequest": "100M", "maxLimit": "500M"}}`), ""},
		{"no suffix", []byte(`{"cpu": {"maxLimit": "3", "defaultLimit": "2", "defaultRequest": "1"}, "memory": {"maxLimit": "3", "defaultLimit": "2", "defaultRequest": "1"}, "ignoreImages": []}`), ""},
		{"invalid cpu settings", []byte(`{"cpu": {"maxLimit": "2m", "defaultRequest": "3m", "defaultLimit": "4m"}, "memory":{ "defaultLimit": "2G", "defaultRequest": "1G", "maxLimit": "3G"}, "ignoreImages": ["image:latest"]}`), "invalid cpu settings"},
		{"invalid memory settings", []byte(`{"cpu": {"maxLimit": "2m", "defaultRequest": "1m", "defaultLimit": "1m"}, "memory":{ "defaultLimit": "2G", "defaultRequest": "3G", "maxLimit": "1G"}, "ignoreImages": ["image:latest"]}`), "invalid memory settings"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings := &Settings{}
			if err := json.Unmarshal(test.rawSettings, settings); err != nil {
				if len(test.errorMessage) == 0 {
					t.Fatalf("Unexpected error: %+v", err)
				}
				if !strings.Contains(err.Error(), test.errorMessage) {
					t.Fatalf("invalid error message. Expected the string '%s' in the error. Got '%s'", test.errorMessage, err.Error())
				}
				return
			}
			err := settings.Valid()
			if len(test.errorMessage) == 0 && err != nil {
				t.Fatalf("unexpected validation error: %+v", err)
			}
			if len(test.errorMessage) > 0 {
				if err == nil {
					t.Fatalf("expected error message with string '%s'. But no error has been returned", test.errorMessage)
				}
				if !strings.Contains(err.Error(), test.errorMessage) {
					t.Errorf("invalid error message. Expected the string '%s' in the error. Got '%s'", test.errorMessage, err.Error())
				}
			}
		})
	}
}

func TestNewSettingsFromValidationReq(t *testing.T) {
	validationReq := &kubewarden_protocol.ValidationRequest{
		Settings: []byte(`{"cpu": {"maxLimit": "3m","defaultRequest": "1m", "defaultLimit": "2m"}, "memory":{"maxLimit": "3G","defaultRequest": "1G", "defaultLimit": "2G"}}`),
	}
	settings, err := NewSettingsFromValidationReq(validationReq)
	if err != nil {
		t.Fatalf("Unexpected error %+v", err)
	}
	expectedCpuValue := resource.MustParse("3m")
	if !settings.Cpu.MaxLimit.Equal(expectedCpuValue) {
		t.Errorf("invalid cpu max limit quantity parsed. Expected %+v, go %+v", expectedCpuValue, settings.Cpu.MaxLimit)
	}
	expectedCpuValue = resource.MustParse("1m")
	if !settings.Cpu.DefaultRequest.Equal(expectedCpuValue) {
		t.Errorf("invalid cpu default request quantity parsed. Expected %+v, go %+v", expectedCpuValue, settings.Cpu.DefaultRequest)
	}
	expectedCpuValue = resource.MustParse("2m")
	if !settings.Cpu.DefaultLimit.Equal(expectedCpuValue) {
		t.Errorf("invalid cpu default limit quantity parsed. Expected %+v, go %+v", expectedCpuValue, settings.Cpu.DefaultLimit)
	}

	expectedMemoryValue := resource.MustParse("3G")
	if !settings.Memory.MaxLimit.Equal(expectedMemoryValue) {
		t.Errorf("invalid memory max limit quantity parsed. Expected %+v, go %+v", expectedMemoryValue, settings.Memory.MaxLimit)
	}
	expectedMemoryValue = resource.MustParse("2G")
	if !settings.Memory.DefaultLimit.Equal(expectedMemoryValue) {
		t.Errorf("invalid memory default limit quantity parsed. Expected %+v, go %+v", expectedMemoryValue, settings.Memory.DefaultLimit)
	}
	expectedMemoryValue = resource.MustParse("1G")
	if !settings.Memory.DefaultRequest.Equal(expectedMemoryValue) {
		t.Errorf("invalid memory default request quantity parsed. Expected %+v, go %+v", expectedMemoryValue, settings.Memory.DefaultRequest)
	}
}

func TestNewSettingsPartialFieldsOnlyFromValidationReq(t *testing.T) {
	t.Run("only memory fields", func(t *testing.T) {
		validationReq := &kubewarden_protocol.ValidationRequest{
			Settings: []byte(`{"memory":{"maxLimit": "3G","defaultRequest": "1G", "defaultLimit": "2G"}}`),
		}
		settings, err := NewSettingsFromValidationReq(validationReq)
		if err != nil {
			t.Fatalf("Unexpected error %+v", err)
		}

		if settings.Cpu != nil {
			t.Fatal("cpu settings should be null")
		}

		expectedMemoryValue := resource.MustParse("3G")
		if !settings.Memory.MaxLimit.Equal(expectedMemoryValue) {
			t.Errorf("invalid memory max limit quantity parsed. Expected %+v, go %+v", expectedMemoryValue, settings.Memory.MaxLimit)
		}
		expectedMemoryValue = resource.MustParse("2G")
		if !settings.Memory.DefaultLimit.Equal(expectedMemoryValue) {
			t.Errorf("invalid memory default limit quantity parsed. Expected %+v, go %+v", expectedMemoryValue, settings.Memory.DefaultLimit)
		}
		expectedMemoryValue = resource.MustParse("1G")
		if !settings.Memory.DefaultRequest.Equal(expectedMemoryValue) {
			t.Errorf("invalid memory default request quantity parsed. Expected %+v, go %+v", expectedMemoryValue, settings.Memory.DefaultRequest)
		}
	})
	t.Run("only cpu fields", func(t *testing.T) {
		validationReq := &kubewarden_protocol.ValidationRequest{
			Settings: []byte(`{"cpu":{"maxLimit": "1","defaultRequest": "1", "defaultLimit": "1"}}`),
		}
		settings, err := NewSettingsFromValidationReq(validationReq)
		if err != nil {
			t.Fatalf("Unexpected error %+v", err)
		}

		if settings.Memory != nil {
			t.Fatal("memory settings should be null")
		}

		expectedCpuValue := resource.MustParse("1")
		if !settings.Cpu.MaxLimit.Equal(expectedCpuValue) {
			t.Errorf("invalid memory max limit quantity parsed. Expected %+v, go %+v", expectedCpuValue, settings.Cpu.MaxLimit)
		}
		if !settings.Cpu.DefaultLimit.Equal(expectedCpuValue) {
			t.Errorf("invalid memory default limit quantity parsed. Expected %+v, go %+v", expectedCpuValue, settings.Cpu.DefaultLimit)
		}
		if !settings.Cpu.DefaultRequest.Equal(expectedCpuValue) {
			t.Errorf("invalid memory default request quantity parsed. Expected %+v, go %+v", expectedCpuValue, settings.Cpu.DefaultRequest)
		}
	})
}
