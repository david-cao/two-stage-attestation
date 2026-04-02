package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/mdlayher/vsock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "github.com/davidcao/attestation-two-stage/agent/api/v1"
	"github.com/davidcao/attestation-two-stage/agent/internal/attestation"
	"github.com/davidcao/attestation-two-stage/agent/internal/server"
)

func main() {
	listen := flag.String("listen", "vsock://:4050", "listen address (vsock://:PORT or tcp://HOST:PORT)")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Set up attestation backends — use real TDX if available, otherwise mock.
	var rtmr attestation.RTMRExtender
	var quoteGen attestation.QuoteGenerator

	if attestation.DetectTDX() {
		log.Println("TDX hardware detected, using real attestation backends")
		var err error
		rtmr, err = attestation.NewTDXRTMRExtender()
		if err != nil {
			log.Fatalf("failed to initialize RTMR extender: %v", err)
		}
		quoteGen = attestation.NewTDXQuoteGenerator()
	} else {
		log.Println("WARNING: TDX hardware not detected, using mock attestation backends")
		rtmr = attestation.NewMockRTMRExtender()
		quoteGen = attestation.NewMockQuoteGenerator()
	}

	srv := server.New(rtmr, quoteGen)

	grpcServer := grpc.NewServer()
	pb.RegisterAttestationAgentServer(grpcServer, srv)
	reflection.Register(grpcServer)

	lis, err := createListener(*listen)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", *listen, err)
	}

	log.Printf("attestation-agent listening on %s", *listen)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("gRPC server failed: %v", err)
	}
}

func createListener(addr string) (net.Listener, error) {
	switch {
	case strings.HasPrefix(addr, "vsock://"):
		portStr := strings.TrimPrefix(addr, "vsock://:")
		var port uint32
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			return nil, fmt.Errorf("parse vsock port %q: %w", portStr, err)
		}
		return vsock.Listen(port, nil)

	case strings.HasPrefix(addr, "tcp://"):
		hostPort := strings.TrimPrefix(addr, "tcp://")
		return net.Listen("tcp", hostPort)

	default:
		return nil, fmt.Errorf("unsupported listen address %q (use vsock://:PORT or tcp://HOST:PORT)", addr)
	}
}

func init() {
	// Ensure we crash loudly rather than silently misbehaving.
	log.SetOutput(os.Stderr)
}
