package server

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestAddressReport_Merge(t *testing.T) {
	time1 := time.Now().UTC().Add(-1 * time.Hour)
	time2 := time.Now().UTC()
	ar1 := &AddressReport{
		LastChecked: time1,
		Labels:      []string{"label1"},
	}
	ar2 := &AddressReport{
		LastChecked: time2,
		Labels:      []string{"label1", "label2"},
	}
	ar1.Merge(ar2)

	assert.Equal(t, &AddressReport{
		LastChecked: time2,
		Labels:      []string{"label1", "label2"},
	}, ar1)
}
