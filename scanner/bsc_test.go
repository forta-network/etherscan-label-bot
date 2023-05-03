package scanner

import (
	"forta-network/go-agent/domain"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
	"context"
	"github.com/chromedp/chromedp"
)

func TestBSCScanner_ExtractName(t *testing.T) {
	scn := &bscParser{}
	b, err := os.ReadFile("./testfiles/bsc.html")
	assert.NoError(t, err)
	name := scn.ExtractName(strings.ToLower(string(b)))
	assert.Equal(t, "fake_phishing1014", name)
}

func TestBSCScanner_ExtractTags(t *testing.T) {
	scn := &bscParser{}
	b, err := os.ReadFile("./testfiles/bsc.html")
	assert.NoError(t, err)
	tags := scn.ExtractTags(strings.ToLower(string(b)))
	assert.Len(t, tags, 1)
	assert.Equal(t, "phish / hack", tags[0])
}

func TestBaseScanner_Scan(t *testing.T) {
	tests := []*scanTest{
		{
			Name:    "phish",
			Address: "0x854c2e14bc43538454d8b0073a6fac2a684729ff",
			Expected: &domain.AddressReport{
				Name: "fake_phishing1014",
				Tags: []string{"phish / hack"},
			},
		},
		{
			Name:    "validator",
			Address: "0x69c77a677c40c7fbea129d4b171a39b7a8ddabfa",
			Expected: &domain.AddressReport{
				Name: "blockorus",
				Tags: []string{"validator"},
			},
		},
	}
	for _, test := range tests {
		scn := &bscParser{}
		ctx, cancel := chromedp.NewContext(context.Background())
		defer cancel()
		res := Scan(scn, test.Address, ctx)
		if test.Expected == nil {
			assert.Nil(t, res)
			continue
		}
		assert.Equal(t, test.Expected.Name, res.Name, test.Name)
		assert.Equal(t, test.Expected.Tags, res.Tags, test.Name)
	}

}
