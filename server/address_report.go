package server

import (
	"golang.org/x/exp/slices"
	"time"
)

type AddressReport struct {
	Name        string    `json:"name"`
	LastChecked time.Time `json:"lastChecked"`
	Tags        []string  `json:"tags"`
}

func (ar *AddressReport) Merge(other *AddressReport) {
	if ar.LastChecked.Before(other.LastChecked) {
		ar.LastChecked = other.LastChecked
	}
	if ar.Name == "" {
		ar.Name = other.Name
	}

	for _, t := range other.Tags {
		if !slices.Contains[string](ar.Tags, t) {
			ar.Tags = append(ar.Tags, t)
		}
	}

}
