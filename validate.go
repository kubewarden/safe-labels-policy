package main

import (
	"fmt"
	"strings"

	"github.com/deckarep/golang-set"
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

	labels := mapset.NewThreadUnsafeSet()
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

	error_msgs := []string{}

	if len(denied_labels_violations) > 0 {
		error_msgs = append(
			error_msgs,
			fmt.Sprintf(
				"The following labels are denied: %s",
				strings.Join(denied_labels_violations, ","),
			))
	}

	if len(constrained_labels_violations) > 0 {
		error_msgs = append(
			error_msgs,
			fmt.Sprintf(
				"The following labels are violating user constraints: %s",
				strings.Join(constrained_labels_violations, ","),
			))
	}

	mandatory_labels_violations := settings.MandatoryLabels.Difference(labels)
	if mandatory_labels_violations.Cardinality() > 0 {
		violations := []string{}
		for _, v := range mandatory_labels_violations.ToSlice() {
			violations = append(violations, v.(string))
		}

		error_msgs = append(
			error_msgs,
			fmt.Sprintf(
				"The following mandatory labels are missing: %s",
				strings.Join(violations, ","),
			))
	}

	if len(error_msgs) > 0 {
		return kubewarden.RejectRequest(
			kubewarden.Message(strings.Join(error_msgs, ". ")),
			kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}
