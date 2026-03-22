package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	mode := flag.String("mode", "client", "Operating mode: client, analyze, baseline")
	addr := flag.String("addr", "https://tls.peet.ws/api/all", "Echo service URL (client mode)")
	ref := flag.String("ref", "", "Path to reference JSON file (default: built-in Chrome 146)")
	utlsPreset := flag.String("utls", "HelloChrome_Auto", "uTLS ClientHello preset (client mode)")
	pcap := flag.String("pcap", "", "Path to pcap/raw file (analyze mode)")
	jsonOut := flag.Bool("json", false, "Output results as JSON")
	out := flag.String("out", "", "Write reference JSON to file (baseline mode)")
	flag.Parse()

	switch *mode {
	case "client":
		runClient(*addr, *ref, *utlsPreset, *jsonOut)
	case "analyze":
		runAnalyze(*pcap, *ref, *jsonOut)
	case "baseline":
		runBaseline(*out, *jsonOut)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", *mode)
		flag.Usage()
		os.Exit(1)
	}
}

func runClient(addr, refFile, utlsPreset string, jsonOut bool) {
	cfg := ClientCheckConfig{
		EchoServiceURL: addr,
		UTLSPreset:     utlsPreset,
		ReferenceFile:  refFile,
	}
	results, actual, err := RunClientCheck(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client check failed: %v\n", err)
		os.Exit(1)
	}
	outputResults(results, actual, jsonOut)
}

func runAnalyze(pcapFile, refFile string, jsonOut bool) {
	if pcapFile == "" {
		fmt.Fprintf(os.Stderr, "analyze mode requires -pcap flag\n")
		os.Exit(1)
	}
	cfg := AnalyzeConfig{
		PcapFile:      pcapFile,
		ReferenceFile: refFile,
	}
	results, actual, err := RunAnalyze(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze failed: %v\n", err)
		os.Exit(1)
	}
	outputResults(results, actual, jsonOut)
}

func runBaseline(outFile string, jsonOut bool) {
	ref := DefaultChrome146Reference()
	if outFile != "" {
		if err := SaveReference(ref, outFile); err != nil {
			fmt.Fprintf(os.Stderr, "save reference: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Reference saved to %s\n", outFile)
		return
	}
	if jsonOut {
		data, err := json.MarshalIndent(ref, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal reference: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		return
	}
	fmt.Printf("Source:        %s\n", ref.Source)
	fmt.Printf("JA4:           %s\n", ref.TLS.JA4)
	fmt.Printf("ALPS:          %d\n", ref.TLS.ALPSCodepoint)
	fmt.Printf("H2 Settings:   %s\n", ref.H2.Settings)
	fmt.Printf("Window Update: %d\n", ref.H2.WindowUpdate)
	fmt.Printf("Pseudo-Header: %s\n", ref.H2.PseudoHeaderOrder)
}

func outputResults(results []CheckResult, actual *Reference, jsonOut bool) {
	if jsonOut {
		out := struct {
			Results []CheckResult `json:"results"`
			Actual  *Reference    `json:"actual,omitempty"`
		}{Results: results, Actual: actual}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal results: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	} else {
		PrintResults(results)
	}

	for _, r := range results {
		if r.Severity == "critical" && !r.Pass {
			os.Exit(1)
		}
	}
}
