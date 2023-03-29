package main

import (
	"encoding/json"
	"testing"

	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func TestEmptySettingsLeadsToRequestAccepted(t *testing.T) {
	settings := RawSettings{
		DeniedLabels:      []string{},
		MandatoryLabels:   []string{},
		ConstrainedLabels: make(map[string]string),
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestRequestAccepted(t *testing.T) {
	settings := RawSettings{
		DeniedLabels:    []string{"bad1", "bad2"},
		MandatoryLabels: []string{},
		ConstrainedLabels: map[string]string{
			"hello": "^world-",
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestAcceptRequestWithConstraintLabel(t *testing.T) {
	settings := RawSettings{
		DeniedLabels:    []string{"bad1", "bad2"},
		MandatoryLabels: []string{},
		ConstrainedLabels: map[string]string{
			"owner": "^team-",
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestRejectionBecauseDeniedLabel(t *testing.T) {
	settings := RawSettings{
		DeniedLabels:    []string{"owner"},
		MandatoryLabels: []string{},
		ConstrainedLabels: map[string]string{
			"hello": "^world-",
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected accept response")
	}

	expectedMessage := "The following labels are denied: owner"
	if *response.Message != expectedMessage {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expectedMessage)
	}
}

func TestRejectionBecauseConstrainedLabelNotValid(t *testing.T) {
	constrainedLabels := make(map[string]*RegularExpression)
	re, err := CompileRegularExpression(`^cc-\d+$`)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
	constrainedLabels["cc-center"] = re

	settings := RawSettings{
		DeniedLabels:    []string{},
		MandatoryLabels: []string{},
		ConstrainedLabels: map[string]string{
			"cc-center": `^cc-\d+$`,
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected accept response")
	}

	expectedMessage := "The following labels are violating user constraints: cc-center"
	if *response.Message != expectedMessage {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expectedMessage)
	}
}

func TestRejectionBecauseConstrainedLabelMissing(t *testing.T) {
	settings := RawSettings{
		DeniedLabels:      []string{},
		MandatoryLabels:   []string{"required"},
		ConstrainedLabels: map[string]string{},
	}

	payload, err := kubewarden_testing.BuildValidationRequestFromFixture(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected accept response")
	}

	expectedMessage := "The following mandatory labels are missing: required"
	if *response.Message != expectedMessage {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expectedMessage)
	}
}
