package scanner

import (
	 "forta-network/go-agent/domain"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
)

func TestArbitrumScanner_ExtractName(t *testing.T) {
	scn := &arbitrumParser{}
	b, err := os.ReadFile("./testfiles/arbitrum.html")
	assert.NoError(t, err)
	name := scn.ExtractName(strings.ToLower(string(b)))
	assert.Equal(t, "aave: aaave token v3", name)
}

func TestArbitrumScanner_ExtractTags(t *testing.T) {
	scn := &arbitrumParser{}
	b, err := os.ReadFile("./testfiles/arbitrum.html")
	assert.NoError(t, err)
	tags := scn.ExtractTags(strings.ToLower(string(b)))
	assert.Len(t, tags, 1)
	assert.Equal(t, "aave", tags[0])
}

func TestArbitrumScanner_Scan(t *testing.T) {
	tests := []*scanTest{
		{
			Name:    "exploit",
			Address: "0xdd0cdb4c3b887bc533957bc32463977e432e49c3",
			Expected: &domain.AddressReport{
				Name: "sentimentxyz exploiter",
				Tags: []string{"exploit"},
			},
		},
		{
			Name:    "arbitrum bridge",
			Address: "0x467194771dae2967aef3ecbedd3bf9a310c76c65",
			Expected: &domain.AddressReport{
				Name: "arbitrum one: l2 dai gateway",
				Tags: []string{"arbitrum", "bridge"},
			},
		},
		{
			Name:    "defi",
			Address: "0xeff77e179f6abb49a5bf0ec25c920b495e110c3b",
			Expected: &domain.AddressReport{
				Name: "zyberswap: earn v1",
				Tags: []string{"defi"},
			},
		},
		{
			Name:    "phishing",
			Address: "0x94546e31a8eca3da6143eff3a0012be3af1ba7b8",
			Expected: &domain.AddressReport{
				Name: "fake_phishing1",
				Tags: []string{"phish-hack"},
			},
		},
	}
	for _, test := range tests {
		scn := &arbitrumParser{}
		res := Scan(scn, test.Address)
		if test.Expected == nil {
			assert.Nil(t, res)
			continue
		}
		assert.Equal(t, test.Expected.Name, res.Name, test.Name)
		assert.Equal(t, test.Expected.Tags, res.Tags, test.Name)
	}

}
