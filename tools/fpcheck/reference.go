package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Reference holds all expected fingerprint values for a browser profile.
type Reference struct {
	Source   string    `json:"source"`
	Captured time.Time `json:"captured"`

	TLS TLSReference `json:"tls"`
	H2  H2Reference  `json:"h2"`
	TCP TCPReference `json:"tcp"`
}

// TLSReference holds TLS ClientHello fingerprint fields.
type TLSReference struct {
	JA4           string   `json:"ja4"`
	Extensions    []uint16 `json:"extensions"`
	ALPSCodepoint uint16   `json:"alps_codepoint"`
	CipherSuites  []uint16 `json:"cipher_suites"`
	ALPN          []string `json:"alpn"`
}

// H2Reference holds HTTP/2 connection-level fingerprint fields.
type H2Reference struct {
	Settings          string `json:"settings"`
	WindowUpdate      uint32 `json:"window_update"`
	Priority          int    `json:"priority"`
	PseudoHeaderOrder string `json:"pseudo_header_order"`
	AkamaiString      string `json:"akamai_string"`
}

// TCPReference holds TCP-level fingerprint fields.
type TCPReference struct {
	JA4T *string `json:"ja4t"`
}

// LoadReference reads a JSON file at path and unmarshals it into a Reference.
func LoadReference(path string) (*Reference, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load reference %s: %w", path, err)
	}
	var ref Reference
	if err := json.Unmarshal(data, &ref); err != nil {
		return nil, fmt.Errorf("parse reference %s: %w", path, err)
	}
	return &ref, nil
}

// SaveReference marshals ref to indented JSON and writes it to path.
func SaveReference(ref *Reference, path string) error {
	data, err := json.MarshalIndent(ref, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal reference: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write reference %s: %w", path, err)
	}
	return nil
}

// DefaultChrome146Reference returns a hardcoded baseline Reference for Chrome 146.
func DefaultChrome146Reference() *Reference {
	return &Reference{
		Source: "Chrome 146 baseline (hardcoded)",
		TLS: TLSReference{
			JA4:           "",
			Extensions:    nil,
			ALPSCodepoint: 17613,
			CipherSuites:  nil,
			ALPN:          []string{"h2", "http/1.1"},
		},
		H2: H2Reference{
			Settings:          "1:65536;2:0;4:6291456;6:262144",
			WindowUpdate:      15663105,
			Priority:          0,
			PseudoHeaderOrder: "m,a,s,p",
			AkamaiString:      "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		},
		TCP: TCPReference{
			JA4T: nil,
		},
	}
}

// CheckResult holds the outcome of a single fingerprint comparison.
type CheckResult struct {
	Vector   string // e.g. "H2 SETTINGS", "TLS JA4", "ALPS codepoint"
	Expected string // expected value
	Actual   string // actual value found
	Pass     bool   // true if match
	Severity string // "critical", "warning", "info"
	Note     string // human-readable explanation
}

// Compare compares actual against expected field by field and returns results.
// Fields in expected that are empty/nil/zero are skipped.
func Compare(actual, expected *Reference) []CheckResult {
	var results []CheckResult

	// --- H2 comparisons (critical) ---
	if expected.H2.Settings != "" {
		results = append(results, CheckResult{
			Vector:   "H2 SETTINGS",
			Expected: expected.H2.Settings,
			Actual:   actual.H2.Settings,
			Pass:     actual.H2.Settings == expected.H2.Settings,
			Severity: "critical",
			Note:     settingsNote(actual.H2.Settings, expected.H2.Settings),
		})
	}

	if expected.H2.WindowUpdate != 0 {
		expStr := fmt.Sprintf("%d", expected.H2.WindowUpdate)
		actStr := fmt.Sprintf("%d", actual.H2.WindowUpdate)
		results = append(results, CheckResult{
			Vector:   "H2 WINDOW_UPDATE",
			Expected: expStr,
			Actual:   actStr,
			Pass:     actual.H2.WindowUpdate == expected.H2.WindowUpdate,
			Severity: "critical",
			Note:     exactNote(actStr, expStr),
		})
	}

	// Priority: 0 is a valid expected value, so always compare if settings is set.
	// We compare even if expected is 0, since 0 means "no priority frames".
	if expected.H2.Settings != "" {
		expStr := fmt.Sprintf("%d", expected.H2.Priority)
		actStr := fmt.Sprintf("%d", actual.H2.Priority)
		pass := actual.H2.Priority == expected.H2.Priority
		note := exactNote(actStr, expStr)
		if pass && expected.H2.Priority == 0 {
			note = "no priority frames"
		}
		results = append(results, CheckResult{
			Vector:   "H2 PRIORITY",
			Expected: expStr,
			Actual:   actStr,
			Pass:     pass,
			Severity: "critical",
			Note:     note,
		})
	}

	if expected.H2.PseudoHeaderOrder != "" {
		results = append(results, CheckResult{
			Vector:   "H2 PSH order",
			Expected: expected.H2.PseudoHeaderOrder,
			Actual:   actual.H2.PseudoHeaderOrder,
			Pass:     actual.H2.PseudoHeaderOrder == expected.H2.PseudoHeaderOrder,
			Severity: "critical",
			Note:     exactNote(actual.H2.PseudoHeaderOrder, expected.H2.PseudoHeaderOrder),
		})
	}

	if expected.H2.AkamaiString != "" {
		results = append(results, CheckResult{
			Vector:   "H2 Akamai string",
			Expected: expected.H2.AkamaiString,
			Actual:   actual.H2.AkamaiString,
			Pass:     actual.H2.AkamaiString == expected.H2.AkamaiString,
			Severity: "critical",
			Note:     exactNote(actual.H2.AkamaiString, expected.H2.AkamaiString),
		})
	}

	// --- TLS comparisons ---
	if expected.TLS.JA4 != "" {
		results = append(results, CheckResult{
			Vector:   "TLS JA4",
			Expected: expected.TLS.JA4,
			Actual:   actual.TLS.JA4,
			Pass:     actual.TLS.JA4 == expected.TLS.JA4,
			Severity: "critical",
			Note:     exactNote(actual.TLS.JA4, expected.TLS.JA4),
		})
	}

	if expected.TLS.ALPSCodepoint != 0 {
		expStr := fmt.Sprintf("%d", expected.TLS.ALPSCodepoint)
		actStr := fmt.Sprintf("%d", actual.TLS.ALPSCodepoint)
		results = append(results, CheckResult{
			Vector:   "TLS ALPS codepoint",
			Expected: expStr,
			Actual:   actStr,
			Pass:     actual.TLS.ALPSCodepoint == expected.TLS.ALPSCodepoint,
			Severity: "warning",
			Note:     exactNote(actStr, expStr),
		})
	}

	if expected.TLS.CipherSuites != nil {
		results = append(results, compareUint16List("TLS CipherSuites", actual.TLS.CipherSuites, expected.TLS.CipherSuites, "warning"))
	}

	if expected.TLS.Extensions != nil {
		results = append(results, compareUint16List("TLS Extensions", actual.TLS.Extensions, expected.TLS.Extensions, "warning"))
	}

	if expected.TLS.ALPN != nil {
		results = append(results, compareStringList("TLS ALPN", actual.TLS.ALPN, expected.TLS.ALPN, "warning"))
	}

	// --- TCP comparisons ---
	if expected.TCP.JA4T != nil {
		actStr := ""
		if actual.TCP.JA4T != nil {
			actStr = *actual.TCP.JA4T
		}
		results = append(results, CheckResult{
			Vector:   "TCP JA4T",
			Expected: *expected.TCP.JA4T,
			Actual:   actStr,
			Pass:     actual.TCP.JA4T != nil && *actual.TCP.JA4T == *expected.TCP.JA4T,
			Severity: "info",
			Note:     exactNote(actStr, *expected.TCP.JA4T),
		})
	}

	return results
}

func exactNote(actual, expected string) string {
	if actual == expected {
		return "exact match"
	}
	return fmt.Sprintf("expected %q, got %q", expected, actual)
}

func settingsNote(actual, expected string) string {
	if actual == expected {
		return "exact match"
	}
	return fmt.Sprintf("settings mismatch: expected %q, got %q", expected, actual)
}

func compareUint16List(vector string, actual, expected []uint16, severity string) CheckResult {
	expStr := formatUint16Slice(expected)
	actStr := formatUint16Slice(actual)

	if len(actual) == len(expected) {
		match := true
		for i := range expected {
			if actual[i] != expected[i] {
				match = false
				break
			}
		}
		if match {
			return CheckResult{
				Vector:   vector,
				Expected: expStr,
				Actual:   actStr,
				Pass:     true,
				Severity: severity,
				Note:     fmt.Sprintf("%d entries, exact match", len(expected)),
			}
		}
	}

	// Build diff details.
	note := listDiffUint16(actual, expected)
	return CheckResult{
		Vector:   vector,
		Expected: expStr,
		Actual:   actStr,
		Pass:     false,
		Severity: severity,
		Note:     note,
	}
}

func compareStringList(vector string, actual, expected []string, severity string) CheckResult {
	expStr := strings.Join(expected, ", ")
	actStr := strings.Join(actual, ", ")

	if len(actual) == len(expected) {
		match := true
		for i := range expected {
			if actual[i] != expected[i] {
				match = false
				break
			}
		}
		if match {
			return CheckResult{
				Vector:   vector,
				Expected: expStr,
				Actual:   actStr,
				Pass:     true,
				Severity: severity,
				Note:     fmt.Sprintf("%d entries, exact match", len(expected)),
			}
		}
	}

	note := listDiffString(actual, expected)
	return CheckResult{
		Vector:   vector,
		Expected: expStr,
		Actual:   actStr,
		Pass:     false,
		Severity: severity,
		Note:     note,
	}
}

func listDiffUint16(actual, expected []uint16) string {
	expSet := make(map[uint16]bool, len(expected))
	for _, v := range expected {
		expSet[v] = true
	}
	actSet := make(map[uint16]bool, len(actual))
	for _, v := range actual {
		actSet[v] = true
	}

	var parts []string

	var missing []uint16
	for _, v := range expected {
		if !actSet[v] {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		parts = append(parts, fmt.Sprintf("missing: %s", formatUint16Slice(missing)))
	}

	var extra []uint16
	for _, v := range actual {
		if !expSet[v] {
			extra = append(extra, v)
		}
	}
	if len(extra) > 0 {
		parts = append(parts, fmt.Sprintf("extra: %s", formatUint16Slice(extra)))
	}

	if len(missing) == 0 && len(extra) == 0 {
		parts = append(parts, "same elements but different order")
	}

	return strings.Join(parts, "; ")
}

func listDiffString(actual, expected []string) string {
	expSet := make(map[string]bool, len(expected))
	for _, v := range expected {
		expSet[v] = true
	}
	actSet := make(map[string]bool, len(actual))
	for _, v := range actual {
		actSet[v] = true
	}

	var parts []string

	var missing []string
	for _, v := range expected {
		if !actSet[v] {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		parts = append(parts, fmt.Sprintf("missing: [%s]", strings.Join(missing, ", ")))
	}

	var extra []string
	for _, v := range actual {
		if !expSet[v] {
			extra = append(extra, v)
		}
	}
	if len(extra) > 0 {
		parts = append(parts, fmt.Sprintf("extra: [%s]", strings.Join(extra, ", ")))
	}

	if len(missing) == 0 && len(extra) == 0 {
		parts = append(parts, "same elements but different order")
	}

	return strings.Join(parts, "; ")
}

func formatUint16Slice(s []uint16) string {
	strs := make([]string, len(s))
	for i, v := range s {
		strs[i] = fmt.Sprintf("%d", v)
	}
	return "[" + strings.Join(strs, ", ") + "]"
}

// PrintResults prints comparison results to stdout with optional ANSI color.
func PrintResults(results []CheckResult) {
	colorEnabled := isColorTerminal()

	green := ""
	red := ""
	yellow := ""
	reset := ""
	if colorEnabled {
		green = "\033[32m"
		red = "\033[31m"
		yellow = "\033[33m"
		reset = "\033[0m"
	}

	fmt.Println("=== Ghost Fingerprint Check ===")

	passCount := 0
	failCount := 0
	skipCount := 0

	// Group by category.
	type entry struct {
		label  string
		value  string
		status string
		note   string
		color  string
	}

	h2Entries := []entry{}
	tlsEntries := []entry{}
	tcpEntries := []entry{}

	for _, r := range results {
		var e entry
		if r.Pass {
			passCount++
			noteStr := ""
			if r.Note != "" && r.Note != "exact match" {
				noteStr = " — " + r.Note
			}
			e = entry{
				label:  vectorLabel(r.Vector),
				value:  displayValue(r),
				status: green + "[PASS" + noteStr + "]" + reset,
			}
		} else {
			failCount++
			e = entry{
				label:  vectorLabel(r.Vector),
				value:  displayValue(r),
				status: red + "[FAIL]" + reset,
				note:   r.Note,
			}
		}

		switch {
		case strings.HasPrefix(r.Vector, "H2"):
			h2Entries = append(h2Entries, e)
		case strings.HasPrefix(r.Vector, "TLS"):
			tlsEntries = append(tlsEntries, e)
		case strings.HasPrefix(r.Vector, "TCP"):
			tcpEntries = append(tcpEntries, e)
		}
	}

	if len(h2Entries) > 0 {
		fmt.Println("HTTP/2:")
		for _, e := range h2Entries {
			fmt.Printf("  %-20s%-40s%s\n", e.label+":", e.value, e.status)
		}
		fmt.Println()
	}

	if len(tlsEntries) > 0 {
		fmt.Println("TLS:")
		for _, e := range tlsEntries {
			fmt.Printf("  %-20s%-40s%s\n", e.label+":", e.value, e.status)
		}
		fmt.Println()
	}

	if len(tcpEntries) > 0 {
		fmt.Println("TCP:")
		for _, e := range tcpEntries {
			fmt.Printf("  %-20s%-40s%s\n", e.label+":", e.value, e.status)
		}
		fmt.Println()
	}

	_ = yellow
	_ = skipCount

	fmt.Printf("Result: %d/%d PASS, %d FAIL, %d SKIP\n",
		passCount, passCount+failCount+skipCount, failCount, skipCount)
}

func vectorLabel(vector string) string {
	// Strip the category prefix for display.
	parts := strings.SplitN(vector, " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return vector
}

func displayValue(r CheckResult) string {
	if r.Actual != "" {
		return r.Actual
	}
	return r.Expected
}

func isColorTerminal() bool {
	// Simple heuristic: check for common terminal indicators.
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") != "" {
		return true
	}
	// On Windows, check for WT_SESSION (Windows Terminal) or ConEmu.
	if os.Getenv("WT_SESSION") != "" || os.Getenv("ConEmuANSI") == "ON" {
		return true
	}
	return false
}
