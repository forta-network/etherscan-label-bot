package server

import (
	"golang.org/x/exp/slices"
	"time"
)

type AddressReport struct {
	LastChecked time.Time `json:"lastChecked"`
	Labels      []string  `json:"detectedLabels"`
}

func (ar *AddressReport) Merge(other *AddressReport) {
	if ar.LastChecked.Before(other.LastChecked) {
		ar.LastChecked = other.LastChecked
	}
	for _, l := range other.Labels {
		if !slices.Contains[string](ar.Labels, l) {
			ar.Labels = append(ar.Labels, l)
		}
	}
}
