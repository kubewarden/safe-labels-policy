package main

import (
	"encoding/json"
	"regexp"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func TestEmptySettingsLeadsToRequestAccepted(t *testing.T) {
	settings := Settings{
		DeniedLabels:      mapset.NewThreadUnsafeSet[string](),
		MandatoryLabels:   mapset.NewThreadUnsafeSet[string](),
		ConstrainedLabels: map[string]*RegularExpression{},
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
	settings := Settings{
		DeniedLabels:    mapset.NewThreadUnsafeSet("bad1", "bad2"),
		MandatoryLabels: mapset.NewThreadUnsafeSet[string](),
		ConstrainedLabels: map[string]*RegularExpression{
			"owner": {
				Regexp: regexp.MustCompile("team-"),
			},
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
	settings := Settings{
		DeniedLabels:    mapset.NewThreadUnsafeSet("bad1", "bad2"),
		MandatoryLabels: mapset.NewThreadUnsafeSet[string](),
		ConstrainedLabels: map[string]*RegularExpression{
			"owner": {
				Regexp: regexp.MustCompile(`^team-`),
			},
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
	settings := Settings{
		DeniedLabels:    mapset.NewThreadUnsafeSet("owner"),
		MandatoryLabels: mapset.NewThreadUnsafeSet[string](),
		ConstrainedLabels: map[string]*RegularExpression{
			"hello": {
				Regexp: regexp.MustCompile(`^world-`),
			},
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

	settings := Settings{
		DeniedLabels:    mapset.NewThreadUnsafeSet[string](),
		MandatoryLabels: mapset.NewThreadUnsafeSet[string](),
		ConstrainedLabels: map[string]*RegularExpression{
			"cc-center": {
				Regexp: regexp.MustCompile(`^cc-\d+$`),
			},
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
	settings := Settings{
		DeniedLabels:      mapset.NewThreadUnsafeSet[string](),
		MandatoryLabels:   mapset.NewThreadUnsafeSet("required"),
		ConstrainedLabels: nil,
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
