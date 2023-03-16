package server

import (
	"context"
	"fmt"
	"github.com/forta-network/forta-core-go/protocol"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"sync"
	"testing"
)

const phishAddress = "0x4d30774eba5421e79626e747948505fd280e4ac0"
const heistAddress = "0x14ec0cd2acee4ce37260b925f74648127a889a28"
const tether = "0xdac17f958d2ee523a2206206994597c13d831ec7"
const existing = "0xd2b1a0e2e733c7c2621963b183e7c769c7e1a94c"

func labelExists(finding *protocol.Finding, l *protocol.Label) bool {
	for _, label := range finding.Labels {
		if l.String() == label.String() {
			return true
		}
	}
	return false
}

func TestExtractName(t *testing.T) {
	b, err := os.ReadFile("./testfiles/test.html")
	assert.NoError(t, err)
	name := extractName(strings.ToLower(string(b)))
	assert.Equal(t, "0x: token sale", name)
}

func TestExtractTags(t *testing.T) {
	b, err := os.ReadFile("./testfiles/yearnhack.html")
	assert.NoError(t, err)
	tags := extractTags(strings.ToLower(string(b)))
	assert.Len(t, tags, 2)
}

func TestAgent_EvaluateTx(t *testing.T) {
	ctx := context.Background()
	tx := &protocol.TransactionEvent{
		Network: &protocol.TransactionEvent_Network{ChainId: "0x1"},
		Addresses: map[string]bool{
			phishAddress: true,
			heistAddress: true,
			tether:       true,
			existing:     true,
		},
	}
	a := &Agent{
		mux:   sync.Mutex{},
		state: make(map[string]*AddressReport),
	}
	res, err := a.EvaluateTx(ctx, &protocol.EvaluateTxRequest{Event: tx})
	assert.NoError(t, err)

	assert.Len(t, res.Findings, 1)

	for _, l := range res.Findings[0].Labels {
		fmt.Println(fmt.Sprintf("%s: %s", l.Entity, l.Label))
	}
	assert.Len(t, res.Findings[0].Labels, 9)

	assert.True(t, labelExists(res.Findings[0], &protocol.Label{
		EntityType: protocol.Label_ADDRESS,
		Entity:     tether,
		Confidence: 1,
		Label:      "name|tether: usdt stablecoin",
	}))
	assert.True(t, labelExists(res.Findings[0], &protocol.Label{
		EntityType: protocol.Label_ADDRESS,
		Entity:     phishAddress,
		Confidence: 1,
		Label:      "phish / hack",
	}))
	assert.True(t, labelExists(res.Findings[0], &protocol.Label{
		EntityType: protocol.Label_ADDRESS,
		Entity:     heistAddress,
		Confidence: 1,
		Label:      "heist",
	}))
}
