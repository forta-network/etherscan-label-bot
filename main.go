package main

import (
	"fmt"
	"forta-network/go-agent/server"
	"github.com/forta-network/forta-core-go/protocol"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net"
	"os"
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
	protocol.RegisterAgentServer(grpcServer, &server.Agent{})

	log.Info("started server")
	if err := grpcServer.Serve(lis); err != nil {
		panic(err)
	}
}
