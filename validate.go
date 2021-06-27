package main

import (
	"fmt"

	"github.com/francoispqt/onelog"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"
)

func validate(payload []byte) ([]byte, error) {
	kl := kubewarden.KubewardenLogWriter{}
	logger := onelog.New(
		&kl,
		onelog.ALL, // shortcut for onelog.DEBUG|onelog.INFO|onelog.WARN|onelog.ERROR|onelog.FATAL,
	)
	logger.Info("info message from tinygo")

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

	data.ForEach(func(key, value gjson.Result) bool {
		label := key.String()

		if settings.DeniedLabels.Contains(label) {
			err = fmt.Errorf("Label %s is on the deny list", label)
			// stop iterating over labels
			return false
		}

		regExp, found := settings.ConstrainedLabels[label]
		if found {
			// This is a constrained label
			if !regExp.Match([]byte(value.String())) {
				err = fmt.Errorf("The value of %s doesn't pass user-defined constraint", label)
				// stop iterating over labels
				return false
			}
		}

		return true
	})

	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}
