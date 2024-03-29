package scanner

import (
	"forta-network/go-agent/domain"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
)

type scanTest struct {
	Name     string
	Address  string
	Expected *domain.AddressReport
}

func TestMainnetParser_ExtractName(t *testing.T) {
	scn := &mainnetParser{}
	b, err := os.ReadFile("./testfiles/test.html")
	assert.NoError(t, err)
	name := scn.ExtractName(strings.ToLower(string(b)))
	assert.Equal(t, "0x: token sale", name)
}

func TestMainnetParser_ExtractTags(t *testing.T) {
	scn := &mainnetParser{}
	b, err := os.ReadFile("./testfiles/yearnhack.html")
	assert.NoError(t, err)
	tags := scn.ExtractTags(strings.ToLower(string(b)))
	assert.Len(t, tags, 2)
}

func TestMainnetParser_Scan(t *testing.T) {
	tests := []*scanTest{
		{
			Name:    "phish",
			Address: "0x4d30774eba5421e79626e747948505fd280e4ac0",
			Expected: &domain.AddressReport{
				Name: "fake_phishing5814",
				Tags: []string{"phish / hack"},
			},
		},
		{
			Name:    "heist",
			Address: "0x14ec0cd2acee4ce37260b925f74648127a889a28",
			Expected: &domain.AddressReport{
				Name: "yearn (ydai) exploiter",
				Tags: []string{"blocked", "heist"},
			},
		},
		{
			Name:    "tether",
			Address: "0xdac17f958d2ee523a2206206994597c13d831ec7",
			Expected: &domain.AddressReport{
				Name: "tether: usdt stablecoin",
				Tags: []string{"bitfinex", "stablecoin", "blocked", "token contract"},
			},
		},
	}
	for _, test := range tests {
		scn := &mainnetParser{}
		res := Scan(scn, test.Address)
		if test.Expected == nil {
			assert.Nil(t, res)
			continue
		}
		assert.Equal(t, test.Expected.Name, res.Name, test.Name)
		assert.Equal(t, test.Expected.Tags, res.Tags, test.Name)
	}

}
