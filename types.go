package main

type RawSettings struct {
	DeniedLabels      []string          `json:"denied_labels"`
	MandatoryLabels   []string          `json:"mandatory_labels"`
	ConstrainedLabels map[string]string `json:"constrained_labels"`
}
