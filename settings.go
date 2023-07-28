package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"
)

type RawSettings struct {
	DeniedLabels      []string          `json:"denied_labels"`
	MandatoryLabels   []string          `json:"mandatory_labels"`
	ConstrainedLabels map[string]string `json:"constrained_labels"`
}

// A wrapper around the standard regexp.Regexp struct
// that implements marshalling and unmarshalling
type RegularExpression struct {
	*regexp.Regexp
}

// Convenience method to build a regular expression
func CompileRegularExpression(expr string) (*RegularExpression, error) {
    nativeRegExp, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}
	return &RegularExpression{nativeRegExp}, nil
}

// UnmarshalText satisfies the encoding.TextMarshaler interface,
// also used by json.Unmarshal.
func (r *RegularExpression) UnmarshalText(text []byte) error {
	nativeRegExp, err := regexp.Compile(string(text))
	if err != nil {
		return err
	}
	r.Regexp = nativeRegExp
	return nil
}

// MarshalText satisfies the encoding.TextMarshaler interface,
// also used by json.Marshal.
func (r *RegularExpression) MarshalText() ([]byte, error) {
	if r.Regexp != nil {
		return []byte(r.Regexp.String()), nil
	}

	return nil, nil
}

type Settings struct {
	DeniedLabels      mapset.Set[string]            `json:"denied_labels"`
	MandatoryLabels   mapset.Set[string]            `json:"mandatory_labels"`
	ConstrainedLabels map[string]*RegularExpression `json:"constrained_labels"`
}

func NewSettingsFromRaw(rawSettings *RawSettings) (Settings, error) {
	deniedLabels := mapset.NewThreadUnsafeSet[string](rawSettings.DeniedLabels...)
	mandatoryLabels := mapset.NewThreadUnsafeSet[string](rawSettings.MandatoryLabels...)

	constrainedLabels := make(map[string]*RegularExpression)
	for key, value := range rawSettings.ConstrainedLabels {
		re, err := CompileRegularExpression(value)
		if err != nil {
			return Settings{}, err
		}
		constrainedLabels[key] = re
	}

	return Settings{
		DeniedLabels:      deniedLabels,
		MandatoryLabels:   mandatoryLabels,
		ConstrainedLabels: constrainedLabels,
	}, nil
}

// Builds a new Settings instance starting from a validation
// request payload:
//
//	{
//	   "request": ...,
//	   "settings": {
//	      "denied_labels": [...],
//	      "mandatory_labels": [...],
//	      "constrained_labels": { ... }
//	   }
//	}
func NewSettingsFromValidationReq(payload []byte) (Settings, error) {
	settingsJson := gjson.GetBytes(payload, "settings")

	rawSettings := RawSettings{}
	err := json.Unmarshal([]byte(settingsJson.Raw), &rawSettings)
	if err != nil {
		return Settings{}, err
	}

	return NewSettingsFromRaw(&rawSettings)
}

// Builds a new Settings instance starting from a Settings
// payload:
//
//	{
//	   "denied_names": [ ... ],
//	   "constrained_labels": { ... }
//	}
func NewSettingsFromValidateSettingsPayload(payload []byte) (Settings, error) {
	rawSettings := RawSettings{}
	err := json.Unmarshal(payload, &rawSettings)
	if err != nil {
		return Settings{}, err
	}

	return NewSettingsFromRaw(&rawSettings)
}

func (s *Settings) Valid() (bool, error) {
	constrainedLabels := mapset.NewThreadUnsafeSet[string]()

	for label := range s.ConstrainedLabels {
		constrainedLabels.Add(label)
	}

	errors := []string{}

	constrainedAndDenied := constrainedLabels.Intersect(s.DeniedLabels)
	if constrainedAndDenied.Cardinality() != 0 {
		violations := constrainedAndDenied.ToSlice()
		errors = append(
			errors,
			fmt.Sprintf(
				"These labels cannot be constrained and denied at the same time: %s",
				strings.Join(violations, ","),
			),
		)
	}

	mandatoryAndDenied := s.MandatoryLabels.Intersect(s.DeniedLabels)
	if mandatoryAndDenied.Cardinality() != 0 {
		violations := mandatoryAndDenied.ToSlice()
		errors = append(
			errors,
			fmt.Sprintf(
				"These labels cannot be mandatory and denied at the same time: %s",
				strings.Join(violations, ","),
			),
		)
	}

	if len(errors) > 0 {
		return false, fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return true, nil
}

func validateSettings(payload []byte) ([]byte, error) {
	settings, err := NewSettingsFromValidateSettingsPayload(payload)
	if err != nil {
		// this happens when one of the user-defined regular expressions are invalid
		return kubewarden.RejectSettings(
			kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}

	valid, err := settings.Valid()
	if valid {
		return kubewarden.AcceptSettings()
	}
	return kubewarden.RejectSettings(
		kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
}
