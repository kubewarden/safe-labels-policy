package main

import (
	"encoding/json"
	"testing"

	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func TestParseValidSettings(t *testing.T) {
	request := `
	{
		"request": "doesn't matter here",
		"settings": {
			"denied_labels": [ "foo", "bar" ],
			"constrained_labels": {
				"cost-center": "cc-\\d+"
			}
		}
	}
	`
	rawRequest := []byte(request)

	settings, err := NewSettingsFromValidationReq(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	expected_denied_labels := []string{"foo", "bar"}
	for _, exp := range expected_denied_labels {
		if !settings.DeniedLabels.Contains(exp) {
			t.Errorf("Missing value %s", exp)
		}
	}

	re, found := settings.ConstrainedLabels["cost-center"]
	if !found {
		t.Error("Didn't find the expected constrained label")
	}

	expected_regexp := `cc-\d+`
	if re.String() != expected_regexp {
		t.Errorf("Execpted regexp to be %v - got %v instead",
			expected_regexp, re.String())
	}
}

func TestParseSettingsWithInvalidRegexp(t *testing.T) {
	request := `
	{
		"request": "doesn't matter here",
		"settings": {
			"denied_labels": [ "foo", "bar" ],
			"constrained_labels": {
				"cost-center": "cc-[a+"
			}
		}
	}
	`
	rawRequest := []byte(request)

	_, err := NewSettingsFromValidationReq(rawRequest)
	if err == nil {
		t.Errorf("Didn'g get expected error")
	}
}

func TestDetectValidSettings(t *testing.T) {
	request := `
	{
		"denied_labels": [ "foo", "bar" ],
		"constrained_labels": {
			"cost-center": "cc-\\d+"
		}
	}
	`
	rawRequest := []byte(request)
	responsePayload, err := validateSettings(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	var response kubewarden_testing.SettingsValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if !response.Valid {
		t.Errorf("Expected settings to be valid: %s", response.Message)
	}
}

func TestDetectNotValidSettingsDueToBrokenRegexp(t *testing.T) {
	request := `
	{
		"denied_labels": [ "foo", "bar" ],
		"constrained_labels": {
			"cost-center": "cc-[a+"
		}
	}
	`
	rawRequest := []byte(request)
	responsePayload, err := validateSettings(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	var response kubewarden_testing.SettingsValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Valid {
		t.Error("Expected settings to not be valid")
	}

	if response.Message != "Provided settings are not valid: error parsing regexp: missing closing ]: `[a+`" {
		t.Errorf("Unexpected validation error message: %s", response.Message)
	}
}

func TestDetectNotValidSettingsDueToConflictingLabels(t *testing.T) {
	request := `
	{
		"denied_labels": [ "foo", "bar", "cost-center" ],
		"constrained_labels": {
			"cost-center": ".*"
		}
	}
	`
	rawRequest := []byte(request)
	responsePayload, err := validateSettings(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	var response kubewarden_testing.SettingsValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Valid {
		t.Error("Expected settings to not be valid")
	}

	if response.Message != "Provided settings are not valid: These labels cannot be constrained and denied at the same time: Set{cost-center}" {
		t.Errorf("Unexpected validation error message: %s", response.Message)
	}
}
