package server

import (
	"context"
	"github.com/forta-network/forta-core-go/protocol"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
)

const phishAddress = "0x4d30774eba5421e79626e747948505fd280e4ac0"
const heistAddress = "0x14ec0cd2acee4ce37260b925f74648127a889a28"
const tether = "0xdac17f958d2ee523a2206206994597c13d831ec7"

func labelExists(finding *protocol.Finding, l *protocol.Label) bool {
	for _, label := range finding.Labels {
		if l.String() == label.String() {
			return true
		}
	}
	return false
}

func TestAgent_EvaluateTx(t *testing.T) {
	ctx := context.Background()
	tx := &protocol.TransactionEvent{
		Network: &protocol.TransactionEvent_Network{ChainId: "0x1"},
		Addresses: map[string]bool{
			phishAddress: true,
			heistAddress: true,
			tether:       true,
		},
	}
	a := &Agent{
		mux:   sync.Mutex{},
		state: make(map[string]*AddressReport),
	}
	res, err := a.EvaluateTx(ctx, &protocol.EvaluateTxRequest{Event: tx})
	assert.NoError(t, err)

	assert.Len(t, res.Findings, 1)
	assert.Len(t, res.Findings[0].Labels, 2)

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
