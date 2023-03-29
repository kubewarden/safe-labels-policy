package main

import (
	"fmt"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"
)

func validate(payload []byte) ([]byte, error) {
	if !gjson.ValidBytes(payload) {
		return kubewarden.RejectRequest(
			kubewarden.Message("Not a valid JSON document"),
			kubewarden.Code(400))
	}

	settings, err := NewSettingsFromValidationReq(payload)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	data := gjson.GetBytes(
		payload,
		"request.object.metadata.labels")

	labels := mapset.NewThreadUnsafeSet[string]()
	denied_labels_violations := []string{}
	constrained_labels_violations := []string{}

	data.ForEach(func(key, value gjson.Result) bool {
		label := key.String()
		labels.Add(label)

		if settings.DeniedLabels.Contains(label) {
			denied_labels_violations = append(denied_labels_violations, label)
			return true
		}

		regExp, found := settings.ConstrainedLabels[label]
		if found {
			// This is a constrained label
			if !regExp.Match([]byte(value.String())) {
				constrained_labels_violations = append(constrained_labels_violations, label)
				return true
			}
		}

		return true
	})

	errorMsgs := []string{}

	if len(denied_labels_violations) > 0 {
		errorMsgs = append(
			errorMsgs,
			fmt.Sprintf(
				"The following labels are denied: %s",
				strings.Join(denied_labels_violations, ","),
			))
	}

	if len(constrained_labels_violations) > 0 {
		errorMsgs = append(
			errorMsgs,
			fmt.Sprintf(
				"The following labels are violating user constraints: %s",
				strings.Join(constrained_labels_violations, ","),
			))
	}

	mandatoryLabelsViolations := settings.MandatoryLabels.Difference(labels)
	if mandatoryLabelsViolations.Cardinality() > 0 {
		violations := mandatoryLabelsViolations.ToSlice()

		errorMsgs = append(
			errorMsgs,
			fmt.Sprintf(
				"The following mandatory labels are missing: %s",
				strings.Join(violations, ","),
			))
	}

	if len(errorMsgs) > 0 {
		return kubewarden.RejectRequest(
			kubewarden.Message(strings.Join(errorMsgs, ". ")),
			kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}
