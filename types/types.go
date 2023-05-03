package types

import (
	"time"
	"sync"
	"context"

	"forta-network/go-agent/domain"
	"github.com/forta-network/forta-core-go/protocol"

)

type Parser interface {
	ExtractName(body string) string
	ExtractTags(body string) []string
	URLPatterns() []string
}

type Label struct {
	ItemId  string `dynamodbav:"itemId"`
	SortKey string `dynamodbav:"sortKey"`
	Entity  string `dynamodbav:"entity"`
	Label   string `dynamodbav:"label"`
}

type LabelStore interface {
	EntityExists(ctx context.Context, entity string) (bool, error)
	GetLabel(ctx context.Context, entity, label string) (*Label, error)
	PutLabel(ctx context.Context, entity, label string) error
}

type Agent struct {
	protocol.UnimplementedAgentServer
	Mux      sync.Mutex
	lastSync time.Time
	State    map[string]*domain.AddressReport
	started  bool
	Parser   Parser
	LStore   LabelStore
	ChromeCtx   context.Context
}


