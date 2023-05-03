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

func TestOptimismScanner_ExtractName(t *testing.T) {
	scn := &optimismParser{}
	b, err := os.ReadFile("./testfiles/optimism.html")
	assert.NoError(t, err)
	name := scn.ExtractName(strings.ToLower(string(b)))
	assert.Equal(t, "hundredfinance exploiter", name)
}

func TestOptimismScanner_ExtractTags(t *testing.T) {
	scn := &optimismParser{}
	b, err := os.ReadFile("./testfiles/optimism.html")
	assert.NoError(t, err)
	tags := scn.ExtractTags(strings.ToLower(string(b)))
	assert.Len(t, tags, 1)
	assert.Equal(t, "exploit", tags[0])
}

func TestOptimismScanner_Scan(t *testing.T) {
	tests := []*scanTest{
		{
			Name:    "exploit",
			Address: "0x155da45d374a286d383839b1ef27567a15e67528",
			Expected: &domain.AddressReport{
				Name: "hundredfinance exploiter",
				Tags: []string{"exploit"},
			},
		},
		{
			Name:    "token",
			Address: "0x9631be8566fc71d91970b10acfdee29f21da6c27",
			Expected: &domain.AddressReport{
				Name: "intelligent monsters: imon token",
				Tags: []string{"token-contract"},
			},
		},
		{
			Name:    "phishing",
			Address: "0x7e2d35a00d73a534d4d5508e557e0b1c6e60c977",
			Expected: &domain.AddressReport{
				Name: "fake_phishing3",
				Tags: []string{"phish-hack"},
			},
		},
	}
	
	for _, test := range tests {
		scn := &optimismParser{}
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
