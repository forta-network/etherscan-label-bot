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

func TestAvalancheScanner_ExtractName(t *testing.T) {
	scn := &avalancheParser{}
	b, err := os.ReadFile("./testfiles/avalanche.html")
	assert.NoError(t, err)
	name := scn.ExtractName(strings.ToLower(string(b)))
	assert.Equal(t, "platypus finance exploiter", name)
}

func TestAvalancheScanner_ExtractTags(t *testing.T) {
	scn := &avalancheParser{}
	b, err := os.ReadFile("./testfiles/avalanche.html")
	assert.NoError(t, err)
	tags := scn.ExtractTags(strings.ToLower(string(b)))
	assert.Len(t, tags, 1)
	assert.Equal(t, "exploit", tags[0])
}

func TestAvalancheScanner_Scan(t *testing.T) {
	tests := []*scanTest{
		{
			Name:    "exploit",
			Address: "0x59e55ac0cb34358b9511bbb3f3c1327bd40523e5",
			Expected: &domain.AddressReport{
				Name: "bitmart hacker",
				Tags: []string{"exploit", "heist"},
			},
		},
		{
			Name:    "phishing",
			Address: "0x6895cd7989eb617116ea96f887a81a03c9c988c5",
			Expected: &domain.AddressReport{
				Name: "fake_phishing16",
				Tags: []string{"phish-hack"},
			},
		},
	}
	
	for _, test := range tests {
		scn := &avalancheParser{}
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
