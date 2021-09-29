package main

import (
	"encoding/json"
	"testing"

	"github.com/deckarep/golang-set"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func TestEmptySettingsLeadsToRequestAccepted(t *testing.T) {
	settings := Settings{
		DeniedLabels:      mapset.NewThreadUnsafeSet(),
		MandatoryLabels:   mapset.NewThreadUnsafeSet(),
		ConstrainedLabels: make(map[string]*RegularExpression),
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestRequestAccepted(t *testing.T) {
	constrainedLabels := make(map[string]*RegularExpression)
	re, err := CompileRegularExpression(`^world-`)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
	constrainedLabels["hello"] = re

	settings := Settings{
		DeniedLabels:      mapset.NewThreadUnsafeSetFromSlice([]interface{}{"bad1", "bad2"}),
		MandatoryLabels:   mapset.NewThreadUnsafeSet(),
		ConstrainedLabels: constrainedLabels,
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestAcceptRequestWithConstraintLabel(t *testing.T) {
	constrainedLabels := make(map[string]*RegularExpression)
	re, err := CompileRegularExpression(`^team-`)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	constrainedLabels["owner"] = re
	settings := Settings{
		DeniedLabels:      mapset.NewThreadUnsafeSetFromSlice([]interface{}{"bad1", "bad2"}),
		MandatoryLabels:   mapset.NewThreadUnsafeSet(),
		ConstrainedLabels: constrainedLabels,
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestRejectionBecauseDeniedLabel(t *testing.T) {
	constrainedLabels := make(map[string]*RegularExpression)
	re, err := CompileRegularExpression(`^world-`)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
	constrainedLabels["hello"] = re

	settings := Settings{
		DeniedLabels:      mapset.NewThreadUnsafeSetFromSlice([]interface{}{"owner"}),
		MandatoryLabels:   mapset.NewThreadUnsafeSet(),
		ConstrainedLabels: constrainedLabels,
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected accept response")
	}

	expected_message := "The following labels are denied: owner"
	if response.Message != expected_message {
		t.Errorf("Got '%s' instead of '%s'", response.Message, expected_message)
	}
}

func TestRejectionBecauseConstrainedLabelNotValid(t *testing.T) {
	constrainedLabels := make(map[string]*RegularExpression)
	re, err := CompileRegularExpression(`^cc-\d+$`)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
	constrainedLabels["cc-center"] = re

	settings := Settings{
		DeniedLabels:      mapset.NewThreadUnsafeSet(),
		MandatoryLabels:   mapset.NewThreadUnsafeSet(),
		ConstrainedLabels: constrainedLabels,
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected accept response")
	}

	expected_message := "The following labels are violating user constraints: cc-center"
	if response.Message != expected_message {
		t.Errorf("Got '%s' instead of '%s'", response.Message, expected_message)
	}
}

func TestRejectionBecauseConstrainedLabelMissing(t *testing.T) {
	settings := Settings{
		DeniedLabels:      mapset.NewThreadUnsafeSet(),
		MandatoryLabels:   mapset.NewThreadUnsafeSetFromSlice([]interface{}{"required"}),
		ConstrainedLabels: make(map[string]*RegularExpression),
	}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/ingress.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected accept response")
	}

	expected_message := "The following mandatory labels are missing: required"
	if response.Message != expected_message {
		t.Errorf("Got '%s' instead of '%s'", response.Message, expected_message)
	}
}
