package main

import (
	"context"
	"fmt"
	"forta-network/go-agent/domain"
	"forta-network/go-agent/scanner"
	"forta-network/go-agent/server"
	"forta-network/go-agent/store"
	"github.com/forta-network/forta-core-go/protocol"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

func main() {
	port := os.Getenv("AGENT_GRPC_PORT")
	if port == "" {
		port = "50051"
	}
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%s", port))
	if err != nil {
		log.WithError(err).Fatalf("failed to listen on port: %s", port)
	}
	grpcServer := grpc.NewServer()

	// try up to 10 times in case there's some race condition
	var secrets *store.Secrets
	for i := 0; i < 10; i++ {
		secrets, err = store.LoadSecrets()
		if err != nil {
			log.WithError(err).Warnf("attempt %d, retrying (waiting 5s)", i)
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}
	if err != nil {
		log.WithError(err).Fatal("failed to load secrets")
	}

	chainIDEnv := os.Getenv("FORTA_CHAIN_ID")
	chainID, err := strconv.ParseInt(chainIDEnv, 10, 64)
	if err != nil {
		log.WithError(err).Fatalf("failed to parse chain id: %s", chainIDEnv)
	}

	db, err := store.NewLabelStore(context.Background(), chainID, os.Getenv("FORTA_BOT_ID"), secrets)
	if err != nil {
		log.WithError(err).Fatal("failed to init label store")
	}

	parser := scanner.NewParser(chainID)
	protocol.RegisterAgentServer(grpcServer, &server.Agent{
		State:  make(map[string]*domain.AddressReport),
		Parser: parser,
		Mux:    sync.Mutex{},
		LStore: db,
	})

	log.Info("started server")
	if err := grpcServer.Serve(lis); err != nil {
		panic(err)
	}
}
