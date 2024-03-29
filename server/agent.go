package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	label_api "forta-network/go-agent/label-api"
	"github.com/forta-network/forta-core-go/protocol"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"forta-network/go-agent/domain"
	"forta-network/go-agent/scanner"
	"forta-network/go-agent/store"
)

func getBotID() string {
	botID := os.Getenv("FORTA_BOT_ID")
	if botID == "" {
		return "0x6f022d4a65f397dffd059e269e1c2b5004d822f905674dbf518d968f744c2ede"
	}
	return botID
}

type Agent struct {
	protocol.UnimplementedAgentServer
	Mux      sync.Mutex
	lastSync time.Time
	State    map[string]*domain.AddressReport
	started  bool
	Parser   scanner.Parser
	LStore   store.LabelStore
}

func (a *Agent) checkAddress(addr string) *domain.AddressReport {
	if a.Parser == nil {
		return nil
	}
	a.Mux.Lock()
	if s, ok := a.State[addr]; ok {
		if time.Since(s.LastChecked) < 72*time.Hour {
			a.Mux.Unlock()
			return s
		}
	}
	a.Mux.Unlock()

	exists, err := a.LStore.EntityExists(context.Background(), addr)
	if err != nil {
		log.WithError(err).Error("error checking for existing entity (ignoring)")
		return nil
	}
	if exists {
		log.WithField("entity", addr).Info("address exists in cache, skipping")
		return nil
	}

	rp := scanner.Scan(a.Parser, addr)
	rp.LastChecked = time.Now()
	if a.State == nil {
		a.State = make(map[string]*domain.AddressReport)
	}
	if s, ok := a.State[addr]; !ok {
		a.State[addr] = rp
	} else {
		s.Merge(rp)
	}
	return a.State[addr]
}

func (a *Agent) Initialize(ctx context.Context, request *protocol.InitializeRequest) (*protocol.InitializeResponse, error) {
	log.Info("bot started")
	return &protocol.InitializeResponse{
		Status: protocol.ResponseStatus_SUCCESS,
	}, nil
}

func errorMsg(msg string) *protocol.EvaluateTxResponse {
	log.WithError(errors.New(msg)).Error("error while processing")
	return &protocol.EvaluateTxResponse{
		Status: protocol.ResponseStatus_ERROR,
		Errors: []*protocol.Error{
			{
				Message: msg,
			},
		},
	}
}

func (a *Agent) filterOutDuplicates(ls []*protocol.Label) ([]*protocol.Label, []*protocol.Label) {
	c := label_api.NewClient(nil)
	var result []*protocol.Label
	var duplicates []*protocol.Label
	for _, proposed := range ls {
		l, err := a.LStore.GetLabel(context.Background(), proposed.Entity, proposed.Label)
		if err != nil {
			log.WithError(err).Error("error checking cache for duplicate detection (ignoring to avoid downtime)")
		}
		if l != nil {
			log.WithFields(log.Fields{
				"label":  proposed.Label,
				"entity": proposed.Entity,
			}).Info("label already exists in cache (avoiding duplicate)")
			duplicates = append(duplicates, proposed)
			continue
		}
		// this invokes multiple times because it's technically faster than most alternatives
		existing, err := c.GetLabels(&label_api.GetLabelsRequest{
			SourceIDs: []string{getBotID()},
			Entities:  []string{proposed.Entity},
			Labels:    []string{proposed.Label},
			Limit:     1,
		})
		if err != nil {
			log.WithError(err).Error("error getting labels for duplicate detection (ignoring to avoid downtime)")
			return ls, nil
		}
		if len(existing) > 0 {
			log.WithFields(log.Fields{
				"label":  proposed.Label,
				"entity": proposed.Entity,
			}).Info("label already exists (avoiding duplicate)")

			if err := a.LStore.PutLabel(context.Background(), proposed.Entity, proposed.Label); err != nil {
				log.WithError(err).Error("error syncing existing label to cache (ignoring)")
			}

			duplicates = append(duplicates, proposed)
		} else {
			result = append(result, proposed)
		}
	}
	return result, duplicates
}

func summarizeToMap(ls []*protocol.Label) map[string]string {
	res := make(map[string]string)
	addrMap := make(map[string][]string)
	for _, r := range ls {
		if _, ok := addrMap[r.Entity]; !ok {
			addrMap[r.Entity] = []string{r.Label}
		} else {
			addrMap[r.Entity] = append(addrMap[r.Entity], r.Label)
		}
	}
	for addr, labelList := range addrMap {
		res[addr] = strings.Join(labelList, "|")
	}
	return res
}

func toJson(i interface{}) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func (a *Agent) EvaluateTx(ctx context.Context, request *protocol.EvaluateTxRequest) (*protocol.EvaluateTxResponse, error) {
	mux := sync.Mutex{}
	grp, ctx := errgroup.WithContext(ctx)
	addresses := make(chan string)
	var result []*protocol.Label
	workers := 10
	if workers > len(request.Event.Addresses) {
		workers = len(request.Event.Addresses)
	}

	for i := 0; i < workers; i++ {
		grp.Go(func() error {
			for address := range addresses {
				ar := a.checkAddress(address)
				if ar == nil {
					continue
				}
				for _, t := range ar.Tags {
					mux.Lock()
					result = append(result, &protocol.Label{
						EntityType: protocol.Label_ADDRESS,
						Entity:     address,
						Confidence: 1,
						Label:      strings.ToLower(t),
					})
					mux.Unlock()
				}
				if ar.Name != "" {
					mux.Lock()
					result = append(result, &protocol.Label{
						EntityType: protocol.Label_ADDRESS,
						Entity:     address,
						Confidence: 1,
						Label:      fmt.Sprintf("name|%s", strings.ReplaceAll(ar.Name, "|", "_")),
					})
					mux.Unlock()
				}
			}
			return nil
		})
	}

	grp.Go(func() error {
		defer close(addresses)
		for address := range request.Event.Addresses {
			addresses <- address
		}
		return nil
	})

	if err := grp.Wait(); err != nil {
		log.WithError(err).Error("error from errgroup")
		return errorMsg(err.Error()), nil
	}

	newLabels, duplicates := a.filterOutDuplicates(result)
	if len(newLabels) > 0 {
		log.WithFields(
			log.Fields{
				"tx":     request.Event.Transaction.Hash,
				"labels": len(newLabels),
			}).Info("returning finding")

		for _, l := range newLabels {
			if err := a.LStore.PutLabel(ctx, l.Entity, l.Label); err != nil {
				log.WithError(err).Error("error syncing existing label to cache (ignoring)")
			}
		}

		newMap := summarizeToMap(newLabels)
		dupeMap := summarizeToMap(duplicates)

		md := map[string]string{
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
			"added":      toJson(newMap),
			"duplicates": toJson(dupeMap),
		}

		return &protocol.EvaluateTxResponse{
			Status: protocol.ResponseStatus_SUCCESS,
			Findings: []*protocol.Finding{
				{
					Protocol:    "ethereum",
					Severity:    protocol.Finding_INFO,
					Type:        protocol.Finding_INFORMATION,
					AlertId:     "label-sync",
					Name:        "Syncing Labels",
					Metadata:    md,
					Labels:      newLabels,
					Description: fmt.Sprintf("Addresses, %d new, %d dupes", len(newLabels), len(duplicates)),
				},
			},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	// none found
	return &protocol.EvaluateTxResponse{
		Status:    protocol.ResponseStatus_SUCCESS,
		Findings:  []*protocol.Finding{},
		Metadata:  map[string]string{},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil

}

func (a *Agent) EvaluateBlock(ctx context.Context, request *protocol.EvaluateBlockRequest) (*protocol.EvaluateBlockResponse, error) {
	resp := &protocol.EvaluateBlockResponse{
		Status:    protocol.ResponseStatus_SUCCESS,
		Metadata:  map[string]string{},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if !a.started {
		a.started = true
		resp.Findings = append(resp.Findings, &protocol.Finding{
			Protocol:    "ethereum",
			Severity:    protocol.Finding_INFO,
			Type:        protocol.Finding_INFORMATION,
			AlertId:     "bot-started",
			Name:        "✅ Bot Launched",
			Description: "At start-up, this bot sends this alert",
		})
	}

	return resp, nil
}
