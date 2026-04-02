package main

import (
	"crypto/sha512"
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
	rtmr2PreHex := flag.String("rtmr2-pre", "", "hex-encoded RTMR[2] before workload extension (from baseline quote)")
	measurementHex := flag.String("measurement", "", "hex-encoded workload measurement extended into RTMR[2]")
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

	// If --rtmr2-pre and --measurement are provided, verify RTMR[2] by
	// computing the expected value: SHA384(rtmr2_pre || measurement).
	if *rtmr2PreHex != "" && *measurementHex != "" {
		rtmr2Pre, err := hex.DecodeString(*rtmr2PreHex)
		if err != nil {
			log.Fatalf("decode --rtmr2-pre: %v", err)
		}
		measurement, err := hex.DecodeString(*measurementHex)
		if err != nil {
			log.Fatalf("decode --measurement: %v", err)
		}

		expected := extendSHA384(rtmr2Pre, measurement)
		expectedHex := hex.EncodeToString(expected)
		actualHex := hex.EncodeToString(m.RTMR2)

		fmt.Printf("\nRTMR[2] verification:\n")
		fmt.Printf("  pre-extension: %s\n", *rtmr2PreHex)
		fmt.Printf("  measurement:   %s\n", *measurementHex)
		fmt.Printf("  expected:      %s\n", expectedHex)
		fmt.Printf("  actual:        %s\n", actualHex)

		if expectedHex != actualHex {
			log.Fatalf("RTMR[2] verification FAILED: expected %s, got %s", expectedHex, actualHex)
		}
		fmt.Println("  RTMR[2] verification: PASSED")
	}

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

func extendSHA384(old, data []byte) []byte {
	combined := make([]byte, len(old)+len(data))
	copy(combined, old)
	copy(combined[len(old):], data)
	h := sha512.Sum384(combined)
	return h[:]
}
