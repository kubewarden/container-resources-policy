package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kubewarden/container-resources-policy/resource"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

func checkSettingsValues(t *testing.T, settings *ResourceConfiguration, expectedMaxLimit, expectedDefaultRequest, expectedDefaultLimit string, expectedIgnoreValues bool) {
	actualMaxLimit := resource.MustParse(expectedMaxLimit)
	if !settings.MaxLimit.Equal(actualMaxLimit) {
		t.Errorf("invalid max limit quantity parsed. Expected %+v, got %+v", actualMaxLimit, settings.MaxLimit)
	}
	actualDefaultRequest := resource.MustParse(expectedDefaultRequest)
	if !settings.DefaultRequest.Equal(actualDefaultRequest) {
		t.Errorf("invalid default request quantity parsed. Expected %+v, got %+v", actualDefaultRequest, settings.DefaultRequest)
	}
	actualDefaultLimit := resource.MustParse(expectedDefaultLimit)
	if !settings.DefaultLimit.Equal(actualDefaultLimit) {
		t.Errorf("invalid default limit quantity parsed. Expected %+v, got %+v", actualDefaultLimit, settings.DefaultLimit)
	}
	if settings.IgnoreValues != expectedIgnoreValues {
		t.Errorf("invalid ignoreValues value. Expected %t, got %t", expectedIgnoreValues, settings.IgnoreValues)
	}
}

func TestParsingResourceConfiguration(t *testing.T) {
	tests := []struct {
		name         string
		rawSettings  []byte
		errorMessage string
	}{
		{"no suffix", []byte(`{"maxLimit": "3", "minRequest": "1", "defaultLimit": "2", "defaultRequest": "1"}`), ""},
		{"valid ignoreValues with valid resource configuration", []byte(`{"maxLimit": "3", "minRequest": "1", "defaultLimit": "2", "defaultRequest": "1", "ignoreValues": true}`), ""},
		{"valid ignoreValues", []byte(`{"maxLimit": "3", "minRequest": "1", "defaultLimit": "2", "defaultRequest": "1", "ignoreValues": false}`), ""},
		{"valid ignoreValues", []byte(`{"ignoreValues": true}`), ""},
		{"invalid ignoreValues", []byte(`{"ignoreValues": false}`), "all the quantities must be defined"},
		{"invalid limit suffix", []byte(`{"maxLimit": "1x", "minRequest": "1x", "defaultLimit": "1m", "defaultRequest": "1m"}`), "quantities must match the regular expression"},
		{"invalid request suffix", []byte(`{"maxLimit": "3m", "minRequest": "1m", "defaultLimit": "2m", "defaultRequest": "1x"}`), "quantities must match the regular expression"},
		{"defaults greater than max limit", []byte(`{"maxLimit": "2m", "defaultRequest": "3m", "defaultLimit": "4m"}`), "default values cannot be greater than the max limit"},
		{"defaults lower than min request", []byte(`{"minRequest": "4m", "defaultRequest": "3m", "defaultLimit": "4m"}`), "default values cannot be smaller than the min request"},
		{"valid resource configuration", []byte(`{"maxLimit": "4G", "defaultLimit": "2G", "defaultRequest": "1G"}`), ""},
		{"valid resource configuration with all fields", []byte(`{"minRequest": "1G", "maxLimit": "4G", "defaultLimit": "2G", "defaultRequest": "1G"}`), ""},
		{"minLimit greater than defaultLimit", []byte(`{"minLimit": "3m", "defaultLimit": "2m", "defaultRequest": "1m"}`), "default values cannot be smaller than the min limit"},
		{"minLimit greater than defaultRequest", []byte(`{"minLimit": "2m", "defaultLimit": "3m", "defaultRequest": "1m"}`), "default values cannot be smaller than the min limit"},
		{"maxRequest less than defaultLimit", []byte(`{"maxRequest": "1m", "defaultLimit": "2m", "defaultRequest": "3m"}`), "default values cannot be greater than the max request"},
		{"maxRequest less than defaultRequest", []byte(`{"maxRequest": "1m", "defaultLimit": "3m", "defaultRequest": "2m"}`), "default values cannot be greater than the max request"},
		{"valid minLimit configuration", []byte(`{"minLimit": "1m", "defaultLimit": "2m", "defaultRequest": "1m"}`), ""},
		{"valid maxRequest configuration", []byte(`{"maxRequest": "3m", "defaultLimit": "2m", "defaultRequest": "1m"}`), ""},
		{"valid minLimit and maxRequest together", []byte(`{"minLimit": "1m", "maxRequest": "3m", "defaultLimit": "2m", "defaultRequest": "2m"}`), ""},
		{"minLimit with maxLimit consistency", []byte(`{"minLimit": "1m", "maxLimit": "4m", "defaultLimit": "2m", "defaultRequest": "1m"}`), ""},
		{"maxRequest with minRequest consistency", []byte(`{"minRequest": "1m", "maxRequest": "4m", "defaultLimit": "3m", "defaultRequest": "2m"}`), ""},
		{"maxRequest greater than maxLimit", []byte(`{"maxRequest": "5m", "maxLimit": "4m", "defaultLimit": "3m", "defaultRequest": "2m"}`), "max request cannot be greater than the max limit"},
		{"minLimit greater than minRequest", []byte(`{"minLimit": "3m", "minRequest": "2m", "defaultLimit": "4m", "defaultRequest": "3m"}`), "min limit cannot be greater than the min request"},
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
	tests := []struct {
		name         string
		rawSettings  []byte
		errorMessage string
	}{
		{"invalid settings", []byte(`{}`), "no settings provided. At least one resource limit or request must be verified"},
		{"valid settings", []byte(`{"cpu": {"maxLimit": "1m", "defaultRequest": "1m", "defaultLimit": "1m"}, "memory":{ "defaultLimit": "200M", "defaultRequest": "100M", "maxLimit": "500M"}, "ignoreImages": ["image:latest"]}`), ""},
		{"valid settings with cpu field only", []byte(`{"cpu": {"maxLimit": "1m", "defaultRequest": "1m", "defaultLimit": "1m"}}`), ""},
		{"valid settings with memory fields only", []byte(`{"memory":{ "defaultLimit": "200M", "defaultRequest": "100M", "maxLimit": "500M"}}`), ""},
		{"no suffix", []byte(`{"cpu": {"maxLimit": "3", "defaultLimit": "2", "defaultRequest": "1"}, "memory": {"maxLimit": "3", "defaultLimit": "2", "defaultRequest": "1"}, "ignoreImages": []}`), ""},
		{"invalid cpu settings", []byte(`{"cpu": {"maxLimit": "2m", "defaultRequest": "3m", "defaultLimit": "4m"}, "memory":{ "defaultLimit": "2G", "defaultRequest": "1G", "maxLimit": "3G"}, "ignoreImages": ["image:latest"]}`), "default values cannot be greater than the max limit"},
		{"invalid memory settings", []byte(`{"cpu": {"maxLimit": "2m", "defaultRequest": "1m", "defaultLimit": "1m"}, "memory":{ "defaultLimit": "2G", "defaultRequest": "3G", "maxLimit": "1G"}, "ignoreImages": ["image:latest"]}`), "default values cannot be greater than the max limit"},
		{"invalid cpu request", []byte(`{"cpu": {"minRequest": "2m", "maxLimit":	"4m", "defaultRequest": "1m", "defaultLimit": "3m"}}`), "default values cannot be smaller than the min request"},
		{"valid settings with empty memory settings", []byte(`{"cpu": {"maxLimit": "1m", "defaultRequest": "1m", "defaultLimit": "1m"}, "memory":{"ignoreValues": false}, "ignoreImages": ["image:latest"]}`), ""},
		{"valid settings with empty cpu settings", []byte(`{"cpu": {"ignoreValues": false}, "memory":{ "defaultLimit": "200M", "defaultRequest": "100M", "maxLimit": "500M", "ignoreValues": false}, "ignoreImages": ["image:latest"]}`), ""},
		{"invalid settings with empty cpu and memory settings", []byte(`{"cpu": {"ignoreValues": false}, "memory":{"ignoreValues": false}, "ignoreImages": ["image:latest"]}`), "invalid cpu settings\nall the quantities must be defined\ninvalid memory settings\nall the quantities must be defined"},
		{"invalid cpu minLimit", []byte(`{"cpu": {"minLimit": "3m", "defaultLimit": "2m", "defaultRequest": "1m"}}`), "default values cannot be smaller than the min limit"},
		{"invalid cpu maxRequest", []byte(`{"cpu": {"maxRequest": "1m", "defaultLimit": "2m", "defaultRequest": "3m"}}`), "default values cannot be greater than the max request"},
		{"invalid memory minLimit", []byte(`{"memory": {"minLimit": "3G", "defaultLimit": "2G", "defaultRequest": "1G"}}`), "default values cannot be smaller than the min limit"},
		{"invalid memory maxRequest", []byte(`{"memory": {"maxRequest": "1G", "defaultLimit": "2G", "defaultRequest": "3G"}}`), "default values cannot be greater than the max request"},
		{"valid settings with minLimit and maxRequest", []byte(`{"cpu": {"minLimit": "1m", "maxLimit": "4m", "maxRequest": "3m", "defaultLimit": "2m", "defaultRequest": "2m"}, "memory": {"minLimit": "1G", "maxLimit": "4G", "maxRequest": "3G", "defaultLimit": "2G", "defaultRequest": "2G"}}`), ""},
		{"invalid cpu maxRequest greater than maxLimit", []byte(`{"cpu": {"maxRequest": "5m", "maxLimit": "4m", "defaultLimit": "3m", "defaultRequest": "2m"}}`), "max request cannot be greater than the max limit"},
		{"invalid cpu minLimit greater than minRequest", []byte(`{"cpu": {"minLimit": "3m", "minRequest": "2m", "defaultLimit": "4m", "defaultRequest": "3m"}}`), "min limit cannot be greater than the min request"},
		{"invalid memory maxRequest greater than maxLimit", []byte(`{"memory": {"maxRequest": "5G", "maxLimit": "4G", "defaultLimit": "3G", "defaultRequest": "2G"}}`), "max request cannot be greater than the max limit"},
		{"invalid memory minLimit greater than minRequest", []byte(`{"memory": {"minLimit": "3G", "minRequest": "2G", "defaultLimit": "4G", "defaultRequest": "3G"}}`), "min limit cannot be greater than the min request"},
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
	checkSettingsValues(t, settings.Cpu, "3m", "1m", "2m", false)
	checkSettingsValues(t, settings.Memory, "3G", "1G", "2G", false)
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
		checkSettingsValues(t, settings.Memory, "3G", "1G", "2G", false)
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

		checkSettingsValues(t, settings.Cpu, "1", "1", "1", false)
	})
	t.Run("only memory fields with ignoreValues", func(t *testing.T) {
		validationReq := &kubewarden_protocol.ValidationRequest{
			Settings: []byte(`{"memory":{"maxLimit": "3G","defaultRequest": "1G", "defaultLimit": "2G", "ignoreValues": true}}`),
		}
		settings, err := NewSettingsFromValidationReq(validationReq)
		if err != nil {
			t.Fatalf("Unexpected error %+v", err)
		}
		if settings.Cpu != nil {
			t.Fatal("cpu settings should be null")
		}
		checkSettingsValues(t, settings.Memory, "3G", "1G", "2G", true)
	})
	t.Run("only cpu fields with ignoreValues", func(t *testing.T) {
		validationReq := &kubewarden_protocol.ValidationRequest{
			Settings: []byte(`{"cpu":{"maxLimit": "1","defaultRequest": "1", "defaultLimit": "1", "ignoreValues": true}}`),
		}
		settings, err := NewSettingsFromValidationReq(validationReq)
		if err != nil {
			t.Fatalf("Unexpected error %+v", err)
		}
		if settings.Memory != nil {
			t.Fatal("memory settings should be null")
		}
		checkSettingsValues(t, settings.Cpu, "1", "1", "1", true)
	})
	t.Run("both cpu and memory fields with ignoreValues", func(t *testing.T) {
		validationReq := &kubewarden_protocol.ValidationRequest{
			Settings: []byte(`{"cpu":{"ignoreValues": true}, "memory":{"ignoreValues": true}}`),
		}
		settings, err := NewSettingsFromValidationReq(validationReq)
		if err != nil {
			t.Fatalf("Unexpected error %+v", err)
		}
		checkSettingsValues(t, settings.Cpu, "0", "0", "0", true)
		checkSettingsValues(t, settings.Memory, "0", "0", "0", true)
	})
}
