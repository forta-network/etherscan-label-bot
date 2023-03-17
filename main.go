package main

import (
	"context"
	"fmt"
	"forta-network/go-agent/server"
	"forta-network/go-agent/store"
	"github.com/forta-network/forta-core-go/protocol"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net"
	"os"
	"sync"
)

func main() {
	port := os.Getenv("AGENT_GRPC_PORT")
	if port == "" {
		port = "50051"
	}
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%s", port))
	if err != nil {
		panic(err)
	}
	grpcServer := grpc.NewServer()
	secrets, err := store.LoadSecrets()
	if err != nil {
		panic(err)
	}
	db, err := store.NewLabelStore(context.Background(), os.Getenv("FORTA_BOT_ID"), secrets)
	if err != nil {
		panic(err)
	}
	protocol.RegisterAgentServer(grpcServer, &server.Agent{
		State:  make(map[string]*server.AddressReport),
		Mux:    sync.Mutex{},
		LStore: db,
	})

	log.Info("started server")
	if err := grpcServer.Serve(lis); err != nil {
		panic(err)
	}
}
