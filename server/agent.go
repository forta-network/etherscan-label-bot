package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"forta-network/go-agent/botdb"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/forta-network/forta-core-go/protocol"
)

var labels = []string{
	"heist", "exploit", "phish / hack",
}

const labelPattern = `--danger'>%s</span>`

var urlPatterns = map[string][]string{
	"0x1": {
		"https://etherscan.io/token/%s",
		"https://etherscan.io/address/%s",
	},
}

const dbName = "labels.json"

type Agent struct {
	protocol.UnimplementedAgentServer
	mux      sync.Mutex
	db       botdb.Client
	lastSync time.Time
	state    map[string]*AddressReport
}

func (a *Agent) getDb() (map[string]*AddressReport, error) {
	if a.db == nil {
		db, err := botdb.NewClient(os.Getenv("FORTA_JWT_PROVIDER_HOST"), os.Getenv("FORTA_JWT_PROVIDER_PORT"))
		if err != nil {
			log.WithError(err).Error("error initializing bot db")
			return nil, err
		}
		a.db = db
	}
	saved, err := a.db.Get(botdb.ScopeBot, dbName)
	if err == botdb.ErrNotFound {
		return make(map[string]*AddressReport), nil
	} else if err != nil {
		log.WithError(err).Error("error getting bot db")
		return nil, err
	}
	var savedDb map[string]*AddressReport
	if err := json.Unmarshal(saved, &savedDb); err != nil {
		log.WithError(err).Error("error unmarshaling saved db")
		return nil, err
	}
	return savedDb, nil
}

func (a *Agent) saveDb(db map[string]*AddressReport) error {
	b, err := json.Marshal(db)
	if err != nil {
		return err
	}
	log.Info("save db")
	return a.db.Put(botdb.ScopeBot, dbName, b)
}

func checkPage(url string) []string {
	logger := log.WithFields(log.Fields{
		"url": url,
	})

	res, err := http.Get(url)
	if err != nil {
		logger.WithError(err).Error("error getting page (skipping)")
		return nil
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		logger.WithError(err).Error("error reading body of page (skipping)")
		return nil
	}
	body := strings.ToLower(string(b))
	var result []string
	for _, l := range labels {
		if strings.Contains(body, fmt.Sprintf(labelPattern, l)) {
			result = append(result, l)
		}
	}
	if len(result) > 0 {
		logger.WithFields(log.Fields{
			"labels": strings.Join(result, ","),
		}).Info("found labels")
	}
	return result
}

func uniq(arr []string) []string {
	uniqMap := make(map[string]bool)
	var result []string
	for _, s := range arr {
		if _, ok := uniqMap[s]; s != "" && !ok {
			uniqMap[s] = true
			result = append(result, s)
		}
	}
	return result
}

func (a *Agent) checkAddress(chainID string, addr string) []string {
	patterns, ok := urlPatterns[chainID]
	if !ok {
		return nil
	}
	a.mux.Lock()
	if s, ok := a.state[addr]; ok {
		if time.Since(s.LastChecked) < 24*time.Hour {
			a.mux.Unlock()
			return s.Labels
		}
	}
	a.mux.Unlock()

	var result []string
	for _, p := range patterns {
		result = append(result, checkPage(fmt.Sprintf(p, addr))...)
	}
	result = uniq(result)
	a.mux.Lock()
	defer a.mux.Unlock()
	if s, ok := a.state[addr]; !ok {
		a.state[addr] = &AddressReport{
			LastChecked: time.Now().UTC(),
			Labels:      result,
		}
	} else {
		s.Merge(&AddressReport{
			LastChecked: time.Now().UTC(),
			Labels:      result,
		})
	}

	return result
}

func (a *Agent) syncDb() error {
	a.mux.Lock()
	defer a.mux.Unlock()

	savedDb, err := a.getDb()
	if err != nil {
		return err
	}

	// initialize to savedDb
	if a.state == nil {
		log.Info("initializing local state")
		a.state = savedDb
		return nil
	}

	// otherwise merge our state into saved db (add only)
	for addr, report := range a.state {
		if savedReport, ok := savedDb[addr]; !ok {
			savedDb[addr] = report
		} else {
			savedReport.Merge(report)
		}
	}
	return a.saveDb(savedDb)
}

func (a *Agent) Initialize(ctx context.Context, request *protocol.InitializeRequest) (*protocol.InitializeResponse, error) {
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

func (a *Agent) EvaluateTx(ctx context.Context, request *protocol.EvaluateTxRequest) (*protocol.EvaluateTxResponse, error) {
	if a.state == nil {
		if err := a.syncDb(); err != nil {
			return errorMsg(err.Error()), nil
		}
	}
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
				ls := a.checkAddress(request.Event.Network.ChainId, address)
				for _, l := range ls {
					mux.Lock()
					result = append(result, &protocol.Label{
						EntityType: protocol.Label_ADDRESS,
						Entity:     address,
						Confidence: 1,
						Label:      l,
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

	if len(result) > 0 {
		log.Info("returning finding")
		return &protocol.EvaluateTxResponse{
			Status: protocol.ResponseStatus_SUCCESS,
			Findings: []*protocol.Finding{
				{
					Protocol: "ethereum",
					Severity: protocol.Finding_HIGH,
					Type:     protocol.Finding_SUSPICIOUS,
					AlertId:  "risky-address-label",
					Name:     "Risky Address",
					Metadata: map[string]string{
						"timestamp": time.Now().UTC().Format(time.RFC3339),
					},
					Labels:      result,
					Description: "a risky address was detected",
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
	if time.Since(a.lastSync) > 5*time.Minute {
		if err := a.syncDb(); err != nil {
			log.WithError(err).Error("error syncing database")
			return &protocol.EvaluateBlockResponse{
				Status: protocol.ResponseStatus_ERROR,
				Errors: []*protocol.Error{
					{
						Message: err.Error(),
					},
				},
			}, nil
		}
		log.Info("synced db")
		a.lastSync = time.Now().UTC()
	}

	return &protocol.EvaluateBlockResponse{
		Status:    protocol.ResponseStatus_SUCCESS,
		Findings:  nil,
		Metadata:  map[string]string{},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}
