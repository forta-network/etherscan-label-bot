package scanner

import (
	"forta-network/go-agent/domain"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
)

func TestFantomScanner_ExtractName(t *testing.T) {
	scn := &fantomParser{}
	b, err := os.ReadFile("./testfiles/fantom.html")
	assert.NoError(t, err)
	name := scn.ExtractName(strings.ToLower(string(b)))
	assert.Equal(t, "curve.fi: 2pool pool", name)
}

func TestFantomScanner_ExtractTags(t *testing.T) {
	scn := &fantomParser{}
	b, err := os.ReadFile("./testfiles/fantom.html")
	assert.NoError(t, err)
	tags := scn.ExtractTags(strings.ToLower(string(b)))
	assert.Len(t, tags, 2)
	assert.Equal(t, "curve-fi", tags[0])
	assert.Equal(t, "token-contract", tags[1])
}

func TestFantomScanner_Scan(t *testing.T) {
	tests := []*scanTest{
		{
			Name:    "exploit",
			Address: "0x11111112542d85b3ef69ae05771c2dccff4faa26",
			Expected: &domain.AddressReport{
				Name: "fake 1inch contract",
				Tags: []string{"exploit", "phish-hack"},
			},
		},
		{
			Name:    "token",
			Address: "0x841fad6eae12c286d1fd18d1d525dffa75c7effe",
			Expected: &domain.AddressReport{
				Name: "spookyswap: boo token",
				Tags: []string{"spookyswap", "token-contract"},
			},
		},
		{
			Name:    "gaming",
			Address: "0xce761d788df608bd21bdd59d6f4b54b2e27f25bb",
			Expected: &domain.AddressReport{
				Name: "rarity",
				Tags: []string{"gaming"},
			},
		},
	}
	
	for _, test := range tests {
		scn := &fantomParser{}
		res := Scan(scn, test.Address)
		if test.Expected == nil {
			assert.Nil(t, res)
			continue
		}
		assert.Equal(t, test.Expected.Name, res.Name, test.Name)
		assert.Equal(t, test.Expected.Tags, res.Tags, test.Name)
	}

}
