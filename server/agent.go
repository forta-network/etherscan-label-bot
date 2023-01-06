package server

import (
	"context"
	"time"

	"github.com/forta-network/forta-core-go/protocol"
)

type Agent struct {
	protocol.UnimplementedAgentServer
}

func (a *Agent) Initialize(ctx context.Context, request *protocol.InitializeRequest) (*protocol.InitializeResponse, error) {
	return &protocol.InitializeResponse{
		Status: protocol.ResponseStatus_SUCCESS,
	}, nil
}

func (a *Agent) EvaluateTx(ctx context.Context, request *protocol.EvaluateTxRequest) (*protocol.EvaluateTxResponse, error) {
	return &protocol.EvaluateTxResponse{
		Status: protocol.ResponseStatus_SUCCESS,
		Findings: []*protocol.Finding{
			{
				Protocol: "ethereum",
				Severity: protocol.Finding_INFO,
				Type:     protocol.Finding_INFORMATION,
				AlertId:  "test-go-alert",
				Name:     "Test Go Alert",
				Metadata: map[string]string{
					"timestamp": time.Now().UTC().Format(time.RFC3339),
				},
				Description: "This is a test alert",
				Addresses:   []string{"test"},
			},
		},
		Metadata:  map[string]string{},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (a *Agent) EvaluateBlock(ctx context.Context, request *protocol.EvaluateBlockRequest) (*protocol.EvaluateBlockResponse, error) {
	return &protocol.EvaluateBlockResponse{
		Status:    protocol.ResponseStatus_SUCCESS,
		Findings:  nil,
		Metadata:  map[string]string{},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}
