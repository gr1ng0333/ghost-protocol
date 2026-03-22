package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"ghost/internal/transport"
)

// peetResponse models the relevant fields from tls.peet.ws/api/all.
type peetResponse struct {
	TLS   peetTLS `json:"tls"`
	HTTP2 peetH2  `json:"http2"`
}

type peetTLS struct {
	JA4                  string          `json:"ja4"`
	TLSVersionNegotiated string          `json:"tls_version_negotiated"`
	Extensions           []peetExtension `json:"extensions"`
}

type peetExtension struct {
	Name string `json:"name"`
}

type peetH2 struct {
	AkamaiFingerprint string `json:"akamai_fingerprint"`
}

type checkResult struct {
	name  string
	value string
	pass  bool
	skip  bool
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fmt.Println("=== Ghost Fingerprint Checker ===")
	fmt.Println()

	// 1. Connect using Ghost transport layer.
	d := transport.NewDialer(transport.DefaultChromeH2Config())
	conn, err := d.Dial(ctx, "tls.peet.ws:443", "tls.peet.ws")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// 2. Fetch fingerprint data.
	body, err := conn.Recv(ctx, "/api/all")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] GET /api/all failed: %v\n", err)
		os.Exit(1)
	}
	defer body.Close()

	data, err := io.ReadAll(body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Read response: %v\n", err)
		os.Exit(1)
	}

	var resp peetResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Parse JSON: %v\n", err)
		os.Exit(1)
	}

	// 3. Run checks.
	var results []checkResult

	results = append(results, checkJA4(resp.TLS.JA4))
	results = append(results, checkH2Fingerprint(resp.HTTP2.AkamaiFingerprint)...)
	results = append(results, checkTLSVersion(resp.TLS.TLSVersionNegotiated))
	results = append(results, checkALPS(resp.TLS.Extensions))

	// 4. Print results.
	fmt.Println()
	passed, total := 0, 0
	for _, r := range results {
		status := "FAIL"
		if r.skip {
			status = "SKIP"
		} else if r.pass {
			status = "PASS"
		}

		if r.skip {
			fmt.Printf("  %-25s %s ... %s\n", r.name+":", r.value, status)
		} else {
			fmt.Printf("  %-25s %s ... %s\n", r.name+":", r.value, status)
			total++
			if r.pass {
				passed++
			}
		}
	}

	fmt.Printf("\n%d/%d checks passed\n", passed, total)

	if passed < total {
		os.Exit(1)
	}
}

func checkJA4(ja4 string) checkResult {
	ok := strings.HasPrefix(ja4, "t13d") && strings.Contains(ja4, "h2")
	return checkResult{name: "JA4", value: ja4, pass: ok}
}

func checkH2Fingerprint(fp string) []checkResult {
	// Akamai format: settings|window_update|priority|pseudo_header_order
	parts := strings.Split(fp, "|")
	var results []checkResult

	if len(parts) < 4 {
		return []checkResult{
			{name: "H2_SETTINGS", value: fp, pass: false},
			{name: "WINDOW_UPDATE", value: "?", pass: false},
			{name: "PRIORITY", value: "?", pass: false},
			{name: "PSEUDO_HEADER_ORDER", value: "?", pass: false},
		}
	}

	// CHECK 2: SETTINGS
	expectedSettings := "1:65536;2:0;4:6291456;6:262144"
	results = append(results, checkResult{
		name:  "H2_SETTINGS",
		value: parts[0],
		pass:  parts[0] == expectedSettings,
	})

	// CHECK 3: WINDOW_UPDATE
	results = append(results, checkResult{
		name:  "WINDOW_UPDATE",
		value: parts[1],
		pass:  parts[1] == "15663105",
	})

	// CHECK 5: PRIORITY
	results = append(results, checkResult{
		name:  "PRIORITY",
		value: parts[2],
		pass:  parts[2] == "0",
	})

	// CHECK 4: Pseudo-header order
	results = append(results, checkResult{
		name:  "PSEUDO_HEADER_ORDER",
		value: parts[3],
		pass:  parts[3] == "m,a,s,p",
	})

	return results
}

func checkTLSVersion(version string) checkResult {
	// tls.peet.ws returns "772" for TLS 1.3 (0x0303 = 771 = TLS 1.2, 0x0304 = 772 = TLS 1.3)
	ok := version == "772" || strings.Contains(strings.ToLower(version), "1.3")
	return checkResult{name: "TLS_VERSION", value: version, pass: ok}
}

func checkALPS(extensions []peetExtension) checkResult {
	if len(extensions) == 0 {
		return checkResult{name: "ALPS", value: "not available in response", skip: true}
	}
	for _, ext := range extensions {
		// ALPS extension is "application_settings" with code 17613
		lower := strings.ToLower(ext.Name)
		if strings.Contains(lower, "application_settings") || strings.Contains(lower, "17613") || strings.Contains(lower, "17513") {
			return checkResult{name: "ALPS", value: "present", pass: true}
		}
	}
	return checkResult{name: "ALPS", value: "absent", pass: false}
}
