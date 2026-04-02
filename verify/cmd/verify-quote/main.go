package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"

	"github.com/davidcao/attestation-two-stage/verify/internal/policy"
)

func main() {
	quotePath := flag.String("quote", "", "path to raw TDX quote blob")
	policyPath := flag.String("policy", "", "path to policy JSON file")
	flag.Parse()

	if *quotePath == "" || *policyPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Load quote.
	quoteBytes, err := os.ReadFile(*quotePath)
	if err != nil {
		log.Fatalf("read quote: %v", err)
	}

	// Parse raw TDX quote (Intel binary format) into protobuf.
	quoteAny, err := abi.QuoteToProto(quoteBytes)
	if err != nil {
		log.Fatalf("parse quote: %v", err)
	}
	quote, ok := quoteAny.(*tdx.QuoteV4)
	if !ok {
		log.Fatalf("unexpected quote type: %T (expected QuoteV4)", quoteAny)
	}

	// Verify quote signature and TCB.
	opts := &verify.Options{}
	if err := verify.TdxQuote(quote, opts); err != nil {
		log.Fatalf("quote verification failed: %v", err)
	}
	fmt.Println("quote signature: VALID")

	// Extract measurements from the quote body.
	body := quote.GetTdQuoteBody()
	if body == nil {
		log.Fatal("quote has no TD quote body")
	}

	rtmrs := body.GetRtmrs()
	if len(rtmrs) < 3 {
		log.Fatalf("quote has %d RTMRs, need at least 3", len(rtmrs))
	}

	m := &policy.Measurements{
		MRTD:  body.GetMrTd(),
		RTMR0: rtmrs[0],
		RTMR1: rtmrs[1],
		RTMR2: rtmrs[2],
	}

	fmt.Printf("MRTD:    %s\n", hex.EncodeToString(m.MRTD))
	fmt.Printf("RTMR[0]: %s\n", hex.EncodeToString(m.RTMR0))
	fmt.Printf("RTMR[1]: %s\n", hex.EncodeToString(m.RTMR1))
	fmt.Printf("RTMR[2]: %s\n", hex.EncodeToString(m.RTMR2))

	// Load and check policy.
	pol, err := policy.LoadPolicy(*policyPath)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}

	if err := pol.Check(m); err != nil {
		log.Fatalf("policy check FAILED: %v", err)
	}

	fmt.Println("policy check: PASSED")
}
