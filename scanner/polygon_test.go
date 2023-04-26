package scanner

import (
	"forta-network/go-agent/domain"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
)

func TestPolygonScanner_ExtractName(t *testing.T) {
	scn := &polygonParser{}
	b, err := os.ReadFile("./testfiles/polygon.html")
	assert.NoError(t, err)
	name := scn.ExtractName(strings.ToLower(string(b)))
	assert.Equal(t, "fake_phishing2", name)
}

func TestPolygonScanner_ExtractTags(t *testing.T) {
	scn := &polygonParser{}
	b, err := os.ReadFile("./testfiles/polygon.html")
	assert.NoError(t, err)
	tags := scn.ExtractTags(strings.ToLower(string(b)))
	assert.Len(t, tags, 1)
	assert.Equal(t, "phish / hack", tags[0])
}

func TestPolygonScanner_Scan(t *testing.T) {
	tests := []*scanTest{
		{
			Name:    "phish",
			Address: "0x81067076dcb7d3168ccf7036117b9d72051205e2",
			Expected: &domain.AddressReport{
				Name: "fake_phishing2",
				Tags: []string{"phish / hack"},
			},
		},
		{
			Name:    "uniswap",
			Address: "0xE592427A0AEce92De3Edee1F18E0157C05861564",
			Expected: &domain.AddressReport{
				Name: "uniswap v3: router",
				Tags: []string{"uniswap"},
			},
		},
		{
			Name:    "aave",
			Address: "0x8437d7c167dfb82ed4cb79cd44b7a32a1dd95c77",
			Expected: &domain.AddressReport{
				Name: "aave: aageur token v3",
				Tags: []string{"aave"},
			},
		},
	}
	for _, test := range tests {
		scn := &polygonParser{}
		res := Scan(scn, test.Address)
		if test.Expected == nil {
			assert.Nil(t, res)
			continue
		}
		assert.Equal(t, test.Expected.Name, res.Name, test.Name)
		assert.Equal(t, test.Expected.Tags, res.Tags, test.Name)
	}

}
