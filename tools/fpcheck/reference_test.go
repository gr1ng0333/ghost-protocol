package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultChrome146Reference(t *testing.T) {
	ref := DefaultChrome146Reference()

	if ref.Source != "Chrome 146 baseline (hardcoded)" {
		t.Errorf("Source = %q, want %q", ref.Source, "Chrome 146 baseline (hardcoded)")
	}

	// TLS
	if ref.TLS.JA4 != "" {
		t.Errorf("TLS.JA4 = %q, want empty", ref.TLS.JA4)
	}
	if ref.TLS.Extensions != nil {
		t.Errorf("TLS.Extensions = %v, want nil", ref.TLS.Extensions)
	}
	if ref.TLS.ALPSCodepoint != 17613 {
		t.Errorf("TLS.ALPSCodepoint = %d, want 17613", ref.TLS.ALPSCodepoint)
	}
	if ref.TLS.CipherSuites != nil {
		t.Errorf("TLS.CipherSuites = %v, want nil", ref.TLS.CipherSuites)
	}
	if len(ref.TLS.ALPN) != 2 || ref.TLS.ALPN[0] != "h2" || ref.TLS.ALPN[1] != "http/1.1" {
		t.Errorf("TLS.ALPN = %v, want [h2, http/1.1]", ref.TLS.ALPN)
	}

	// H2
	if ref.H2.Settings != "1:65536;2:0;4:6291456;6:262144" {
		t.Errorf("H2.Settings = %q, want %q", ref.H2.Settings, "1:65536;2:0;4:6291456;6:262144")
	}
	if ref.H2.WindowUpdate != 15663105 {
		t.Errorf("H2.WindowUpdate = %d, want 15663105", ref.H2.WindowUpdate)
	}
	if ref.H2.Priority != 0 {
		t.Errorf("H2.Priority = %d, want 0", ref.H2.Priority)
	}
	if ref.H2.PseudoHeaderOrder != "m,a,s,p" {
		t.Errorf("H2.PseudoHeaderOrder = %q, want %q", ref.H2.PseudoHeaderOrder, "m,a,s,p")
	}
	if ref.H2.AkamaiString != "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p" {
		t.Errorf("H2.AkamaiString = %q, want %q", ref.H2.AkamaiString, "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")
	}

	// TCP
	if ref.TCP.JA4T != nil {
		t.Errorf("TCP.JA4T = %v, want nil", ref.TCP.JA4T)
	}
}

func TestCompare_AllMatch(t *testing.T) {
	a := DefaultChrome146Reference()
	b := DefaultChrome146Reference()

	results := Compare(a, b)
	for _, r := range results {
		if !r.Pass {
			t.Errorf("vector %q: expected PASS, got FAIL (expected=%q actual=%q note=%q)",
				r.Vector, r.Expected, r.Actual, r.Note)
		}
	}
	if len(results) == 0 {
		t.Error("expected at least one comparison result")
	}
}

func TestCompare_SettingsMismatch(t *testing.T) {
	expected := DefaultChrome146Reference()
	actual := DefaultChrome146Reference()
	actual.H2.Settings = "1:65536;2:1;4:6291456;6:262144" // changed 2:0 → 2:1

	results := Compare(actual, expected)

	found := false
	for _, r := range results {
		if r.Vector == "H2 SETTINGS" {
			found = true
			if r.Pass {
				t.Error("H2 SETTINGS should FAIL on mismatch")
			}
			if r.Severity != "critical" {
				t.Errorf("H2 SETTINGS severity = %q, want critical", r.Severity)
			}
		}
	}
	if !found {
		t.Error("H2 SETTINGS check not found in results")
	}
}

func TestCompare_SkipEmptyFields(t *testing.T) {
	expected := &Reference{
		TLS: TLSReference{
			JA4:        "",  // empty → should skip
			Extensions: nil, // nil → should skip
			ALPN:       nil, // nil → should skip
		},
		H2: H2Reference{
			Settings: "1:65536;2:0;4:6291456;6:262144",
		},
	}
	actual := DefaultChrome146Reference()

	results := Compare(actual, expected)

	for _, r := range results {
		if r.Vector == "TLS JA4" {
			t.Error("TLS JA4 should be skipped when expected is empty")
		}
		if r.Vector == "TLS Extensions" {
			t.Error("TLS Extensions should be skipped when expected is nil")
		}
		if r.Vector == "TLS ALPN" {
			t.Error("TLS ALPN should be skipped when expected is nil")
		}
	}
}

func TestCompare_ListMismatch(t *testing.T) {
	expected := &Reference{
		TLS: TLSReference{
			CipherSuites: []uint16{0x1301, 0x1302, 0x1303},
		},
	}
	actual := &Reference{
		TLS: TLSReference{
			CipherSuites: []uint16{0x1302, 0x1301, 0x1303}, // different order
		},
	}

	results := Compare(actual, expected)

	found := false
	for _, r := range results {
		if r.Vector == "TLS CipherSuites" {
			found = true
			if r.Pass {
				t.Error("TLS CipherSuites should FAIL on order mismatch")
			}
			if r.Severity != "warning" {
				t.Errorf("TLS CipherSuites severity = %q, want warning", r.Severity)
			}
			if r.Note == "" {
				t.Error("expected a non-empty note explaining the diff")
			}
		}
	}
	if !found {
		t.Error("TLS CipherSuites check not found in results")
	}
}

func TestSaveAndLoadReference(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ref.json")

	original := DefaultChrome146Reference()
	if err := SaveReference(original, path); err != nil {
		t.Fatalf("SaveReference: %v", err)
	}

	loaded, err := LoadReference(path)
	if err != nil {
		t.Fatalf("LoadReference: %v", err)
	}

	// Compare key fields for round-trip equality.
	if loaded.Source != original.Source {
		t.Errorf("Source = %q, want %q", loaded.Source, original.Source)
	}
	if loaded.H2.Settings != original.H2.Settings {
		t.Errorf("H2.Settings = %q, want %q", loaded.H2.Settings, original.H2.Settings)
	}
	if loaded.H2.WindowUpdate != original.H2.WindowUpdate {
		t.Errorf("H2.WindowUpdate = %d, want %d", loaded.H2.WindowUpdate, original.H2.WindowUpdate)
	}
	if loaded.H2.AkamaiString != original.H2.AkamaiString {
		t.Errorf("H2.AkamaiString = %q, want %q", loaded.H2.AkamaiString, original.H2.AkamaiString)
	}
	if loaded.TLS.ALPSCodepoint != original.TLS.ALPSCodepoint {
		t.Errorf("TLS.ALPSCodepoint = %d, want %d", loaded.TLS.ALPSCodepoint, original.TLS.ALPSCodepoint)
	}
	if len(loaded.TLS.ALPN) != len(original.TLS.ALPN) {
		t.Errorf("TLS.ALPN length = %d, want %d", len(loaded.TLS.ALPN), len(original.TLS.ALPN))
	}
	if loaded.TCP.JA4T != nil {
		t.Errorf("TCP.JA4T = %v, want nil", loaded.TCP.JA4T)
	}

	// Verify JSON is valid by re-reading raw bytes.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !json.Valid(data) {
		t.Error("saved file is not valid JSON")
	}
}

func TestLoadReference_FileNotFound(t *testing.T) {
	_, err := LoadReference("/nonexistent/path/ref.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !os.IsNotExist(unwrapAll(err)) {
		// Accept any error that mentions the file problem.
		t.Logf("error (acceptable): %v", err)
	}
}

func TestLoadReference_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")

	if err := os.WriteFile(path, []byte("{invalid json!!!"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadReference(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	t.Logf("error (expected): %v", err)
}

// unwrapAll fully unwraps an error chain.
func unwrapAll(err error) error {
	for {
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
}

// ──────── vectorLabel ────────

func TestVectorLabel(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"H2 SETTINGS", "SETTINGS"},
		{"TLS JA4", "JA4"},
		{"TCP JA4T", "JA4T"},
		{"NOSPACE", "NOSPACE"},
	}
	for _, tt := range tests {
		got := vectorLabel(tt.input)
		if got != tt.want {
			t.Errorf("vectorLabel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ──────── displayValue ────────

func TestDisplayValue(t *testing.T) {
	r1 := CheckResult{Actual: "actual_val", Expected: "expected_val"}
	if got := displayValue(r1); got != "actual_val" {
		t.Errorf("displayValue with actual = %q, want %q", got, "actual_val")
	}
	r2 := CheckResult{Actual: "", Expected: "expected_val"}
	if got := displayValue(r2); got != "expected_val" {
		t.Errorf("displayValue without actual = %q, want %q", got, "expected_val")
	}
}

// ──────── isColorTerminal ────────

func TestIsColorTerminal(t *testing.T) {
	// Save and restore env vars
	origNoColor := os.Getenv("NO_COLOR")
	origTerm := os.Getenv("TERM")
	origWT := os.Getenv("WT_SESSION")
	origConEmu := os.Getenv("ConEmuANSI")
	defer func() {
		os.Setenv("NO_COLOR", origNoColor)
		os.Setenv("TERM", origTerm)
		os.Setenv("WT_SESSION", origWT)
		os.Setenv("ConEmuANSI", origConEmu)
	}()

	// NO_COLOR set → false
	os.Setenv("NO_COLOR", "1")
	os.Setenv("TERM", "")
	os.Setenv("WT_SESSION", "")
	os.Setenv("ConEmuANSI", "")
	if isColorTerminal() {
		t.Error("isColorTerminal should be false when NO_COLOR is set")
	}

	// TERM set → true
	os.Setenv("NO_COLOR", "")
	os.Setenv("TERM", "xterm-256color")
	if !isColorTerminal() {
		t.Error("isColorTerminal should be true when TERM is set")
	}

	// WT_SESSION set → true
	os.Setenv("TERM", "")
	os.Setenv("WT_SESSION", "some-session-id")
	if !isColorTerminal() {
		t.Error("isColorTerminal should be true when WT_SESSION is set")
	}

	// ConEmuANSI=ON → true
	os.Setenv("WT_SESSION", "")
	os.Setenv("ConEmuANSI", "ON")
	if !isColorTerminal() {
		t.Error("isColorTerminal should be true when ConEmuANSI=ON")
	}

	// Nothing set → false
	os.Setenv("ConEmuANSI", "")
	if isColorTerminal() {
		t.Error("isColorTerminal should be false when nothing is set")
	}
}

// ──────── exactNote ────────

func TestExactNote(t *testing.T) {
	if got := exactNote("foo", "foo"); got != "exact match" {
		t.Errorf("exactNote matching = %q, want 'exact match'", got)
	}
	if got := exactNote("foo", "bar"); !strings.Contains(got, "expected") {
		t.Errorf("exactNote mismatch = %q, want it to contain 'expected'", got)
	}
}

// ──────── settingsNote ────────

func TestSettingsNote(t *testing.T) {
	if got := settingsNote("a", "a"); got != "exact match" {
		t.Errorf("settingsNote matching = %q, want 'exact match'", got)
	}
	if got := settingsNote("a", "b"); !strings.Contains(got, "mismatch") {
		t.Errorf("settingsNote mismatch = %q, want it to contain 'mismatch'", got)
	}
}

// ──────── compareStringList ────────

func TestCompareStringList_Match(t *testing.T) {
	r := compareStringList("TLS ALPN", []string{"h2", "http/1.1"}, []string{"h2", "http/1.1"}, "warning")
	if !r.Pass {
		t.Error("compareStringList should pass for identical lists")
	}
	if !strings.Contains(r.Note, "exact match") {
		t.Errorf("note = %q, want 'exact match'", r.Note)
	}
}

func TestCompareStringList_DiffOrder(t *testing.T) {
	r := compareStringList("TLS ALPN", []string{"http/1.1", "h2"}, []string{"h2", "http/1.1"}, "warning")
	if r.Pass {
		t.Error("compareStringList should fail for different order")
	}
	if !strings.Contains(r.Note, "different order") {
		t.Errorf("note = %q, want it to mention 'different order'", r.Note)
	}
}

func TestCompareStringList_MissingAndExtra(t *testing.T) {
	r := compareStringList("test", []string{"a", "c"}, []string{"a", "b"}, "info")
	if r.Pass {
		t.Error("compareStringList should fail")
	}
	if !strings.Contains(r.Note, "missing") || !strings.Contains(r.Note, "extra") {
		t.Errorf("note = %q, want it to mention both missing and extra", r.Note)
	}
}

// ──────── listDiffString ────────

func TestListDiffString(t *testing.T) {
	// Missing items
	diff := listDiffString([]string{"a"}, []string{"a", "b"})
	if !strings.Contains(diff, "missing") {
		t.Errorf("listDiffString(missing) = %q, want 'missing'", diff)
	}

	// Extra items
	diff = listDiffString([]string{"a", "c"}, []string{"a"})
	if !strings.Contains(diff, "extra") {
		t.Errorf("listDiffString(extra) = %q, want 'extra'", diff)
	}

	// Same elements different order
	diff = listDiffString([]string{"b", "a"}, []string{"a", "b"})
	if !strings.Contains(diff, "different order") {
		t.Errorf("listDiffString(order) = %q, want 'different order'", diff)
	}
}

// ──────── listDiffUint16 additional cases ────────

func TestListDiffUint16_Extra(t *testing.T) {
	diff := listDiffUint16([]uint16{1, 2, 3}, []uint16{1, 2})
	if !strings.Contains(diff, "extra") {
		t.Errorf("listDiffUint16 = %q, want 'extra'", diff)
	}
}

func TestListDiffUint16_Missing(t *testing.T) {
	diff := listDiffUint16([]uint16{1}, []uint16{1, 2})
	if !strings.Contains(diff, "missing") {
		t.Errorf("listDiffUint16 = %q, want 'missing'", diff)
	}
}

func TestListDiffUint16_SameOrder(t *testing.T) {
	diff := listDiffUint16([]uint16{2, 1}, []uint16{1, 2})
	if !strings.Contains(diff, "different order") {
		t.Errorf("listDiffUint16 = %q, want 'different order'", diff)
	}
}

// ──────── formatUint16Slice ────────

func TestFormatUint16Slice(t *testing.T) {
	got := formatUint16Slice([]uint16{1, 2, 3})
	if got != "[1, 2, 3]" {
		t.Errorf("formatUint16Slice = %q, want %q", got, "[1, 2, 3]")
	}
	got = formatUint16Slice(nil)
	if got != "[]" {
		t.Errorf("formatUint16Slice(nil) = %q, want %q", got, "[]")
	}
}

// ──────── PrintResults ────────

func TestPrintResults(t *testing.T) {
	// Save and restore env vars to control color
	origNoColor := os.Getenv("NO_COLOR")
	defer os.Setenv("NO_COLOR", origNoColor)
	os.Setenv("NO_COLOR", "1")

	results := []CheckResult{
		{Vector: "H2 SETTINGS", Expected: "1:65536", Actual: "1:65536", Pass: true, Severity: "critical", Note: "exact match"},
		{Vector: "TLS JA4", Expected: "t13d1517h2_abc_def", Actual: "t13d1517h2_xyz_def", Pass: false, Severity: "critical", Note: "expected \"t13d1517h2_abc_def\", got \"t13d1517h2_xyz_def\""},
		{Vector: "TLS ALPS codepoint", Expected: "17613", Actual: "17613", Pass: true, Severity: "warning", Note: "exact match"},
		{Vector: "TCP JA4T", Expected: "foo", Actual: "", Pass: false, Severity: "info", Note: "expected \"foo\", got \"\""},
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	PrintResults(results)

	w.Close()
	os.Stdout = old
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "Ghost Fingerprint Check") {
		t.Error("output missing header")
	}
	if !strings.Contains(output, "PASS") {
		t.Error("output missing PASS")
	}
	if !strings.Contains(output, "FAIL") {
		t.Error("output missing FAIL")
	}
	if !strings.Contains(output, "Result:") {
		t.Error("output missing Result line")
	}
}

func TestPrintResults_WithColor(t *testing.T) {
	origNoColor := os.Getenv("NO_COLOR")
	origTerm := os.Getenv("TERM")
	defer func() {
		os.Setenv("NO_COLOR", origNoColor)
		os.Setenv("TERM", origTerm)
	}()
	os.Setenv("NO_COLOR", "")
	os.Setenv("TERM", "xterm-256color")

	results := []CheckResult{
		{Vector: "H2 SETTINGS", Expected: "a", Actual: "a", Pass: true, Severity: "critical"},
		{Vector: "TLS JA4", Expected: "a", Actual: "b", Pass: false, Severity: "critical", Note: "mismatch"},
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	PrintResults(results)

	w.Close()
	os.Stdout = old
	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Should contain ANSI escape codes
	if !strings.Contains(output, "\033[") {
		t.Error("output should contain ANSI escape codes when TERM is set")
	}
}

func TestPrintResults_Empty(t *testing.T) {
	origNoColor := os.Getenv("NO_COLOR")
	defer os.Setenv("NO_COLOR", origNoColor)
	os.Setenv("NO_COLOR", "1")

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	PrintResults(nil)

	w.Close()
	os.Stdout = old
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "Result: 0/0") {
		t.Errorf("output = %q, want 'Result: 0/0'", output)
	}
}

// ──────── Compare additional paths ────────

func TestCompare_TLS_JA4(t *testing.T) {
	expected := &Reference{
		TLS: TLSReference{JA4: "t13d1517h2_abc_def"},
	}
	actual := &Reference{
		TLS: TLSReference{JA4: "t13d1517h2_abc_def"},
	}
	results := Compare(actual, expected)
	found := false
	for _, r := range results {
		if r.Vector == "TLS JA4" {
			found = true
			if !r.Pass {
				t.Error("TLS JA4 should pass on exact match")
			}
		}
	}
	if !found {
		t.Error("TLS JA4 check not found")
	}
}

func TestCompare_TLS_JA4_Mismatch(t *testing.T) {
	expected := &Reference{
		TLS: TLSReference{JA4: "t13d1517h2_abc_def"},
	}
	actual := &Reference{
		TLS: TLSReference{JA4: "t13d1517h2_xyz_def"},
	}
	results := Compare(actual, expected)
	for _, r := range results {
		if r.Vector == "TLS JA4" && r.Pass {
			t.Error("TLS JA4 should fail on mismatch")
		}
	}
}

func TestCompare_ALPS_Mismatch(t *testing.T) {
	expected := &Reference{
		TLS: TLSReference{ALPSCodepoint: 17613},
	}
	actual := &Reference{
		TLS: TLSReference{ALPSCodepoint: 17513},
	}
	results := Compare(actual, expected)
	found := false
	for _, r := range results {
		if r.Vector == "TLS ALPS codepoint" {
			found = true
			if r.Pass {
				t.Error("ALPS should fail on mismatch")
			}
		}
	}
	if !found {
		t.Error("ALPS check not found")
	}
}

func TestCompare_TCP_JA4T(t *testing.T) {
	ja4t := "abc123"
	expected := &Reference{TCP: TCPReference{JA4T: &ja4t}}
	actual := &Reference{TCP: TCPReference{JA4T: &ja4t}}
	results := Compare(actual, expected)
	found := false
	for _, r := range results {
		if r.Vector == "TCP JA4T" {
			found = true
			if !r.Pass {
				t.Error("TCP JA4T should pass on match")
			}
		}
	}
	if !found {
		t.Error("TCP JA4T not found")
	}
}

func TestCompare_TCP_JA4T_MismatchNilActual(t *testing.T) {
	ja4t := "abc123"
	expected := &Reference{TCP: TCPReference{JA4T: &ja4t}}
	actual := &Reference{TCP: TCPReference{JA4T: nil}}
	results := Compare(actual, expected)
	for _, r := range results {
		if r.Vector == "TCP JA4T" && r.Pass {
			t.Error("TCP JA4T should fail when actual is nil")
		}
	}
}

func TestCompare_WindowUpdate_Mismatch(t *testing.T) {
	expected := &Reference{H2: H2Reference{WindowUpdate: 15663105}}
	actual := &Reference{H2: H2Reference{WindowUpdate: 12345}}
	results := Compare(actual, expected)
	for _, r := range results {
		if r.Vector == "H2 WINDOW_UPDATE" && r.Pass {
			t.Error("WINDOW_UPDATE should fail on mismatch")
		}
	}
}

func TestCompare_PseudoHeaderOrder_Mismatch(t *testing.T) {
	expected := &Reference{H2: H2Reference{PseudoHeaderOrder: "m,a,s,p"}}
	actual := &Reference{H2: H2Reference{PseudoHeaderOrder: "m,s,a,p"}}
	results := Compare(actual, expected)
	for _, r := range results {
		if r.Vector == "H2 PSH order" && r.Pass {
			t.Error("PSH order should fail on mismatch")
		}
	}
}

func TestCompare_AkamaiString_Mismatch(t *testing.T) {
	expected := &Reference{H2: H2Reference{AkamaiString: "1:65536|15663105|0|m,a,s,p"}}
	actual := &Reference{H2: H2Reference{AkamaiString: "different"}}
	results := Compare(actual, expected)
	for _, r := range results {
		if r.Vector == "H2 Akamai string" && r.Pass {
			t.Error("Akamai string should fail on mismatch")
		}
	}
}

func TestCompare_Priority_Match_Zero(t *testing.T) {
	expected := &Reference{H2: H2Reference{Settings: "1:65536", Priority: 0}}
	actual := &Reference{H2: H2Reference{Settings: "1:65536", Priority: 0}}
	results := Compare(actual, expected)
	for _, r := range results {
		if r.Vector == "H2 PRIORITY" {
			if !r.Pass {
				t.Error("Priority should pass when both zero")
			}
			if !strings.Contains(r.Note, "no priority") {
				t.Errorf("note = %q, want it to contain 'no priority'", r.Note)
			}
		}
	}
}

func TestCompare_Priority_Mismatch(t *testing.T) {
	expected := &Reference{H2: H2Reference{Settings: "1:65536", Priority: 0}}
	actual := &Reference{H2: H2Reference{Priority: 5}}
	results := Compare(actual, expected)
	for _, r := range results {
		if r.Vector == "H2 PRIORITY" && r.Pass {
			t.Error("Priority should fail on mismatch")
		}
	}
}

func TestCompare_Extensions(t *testing.T) {
	expected := &Reference{
		TLS: TLSReference{Extensions: []uint16{0, 23, 51, 13, 43}},
	}
	actual := &Reference{
		TLS: TLSReference{Extensions: []uint16{0, 23, 51, 13, 43}},
	}
	results := Compare(actual, expected)
	for _, r := range results {
		if r.Vector == "TLS Extensions" && !r.Pass {
			t.Error("TLS Extensions should pass on exact match")
		}
	}
}

func TestCompare_ALPN(t *testing.T) {
	expected := &Reference{
		TLS: TLSReference{ALPN: []string{"h2", "http/1.1"}},
	}
	actual := &Reference{
		TLS: TLSReference{ALPN: []string{"h2", "http/1.1"}},
	}
	results := Compare(actual, expected)
	for _, r := range results {
		if r.Vector == "TLS ALPN" && !r.Pass {
			t.Error("TLS ALPN should pass on exact match")
		}
	}
}

// ──────── outputResults ────────

func TestOutputResults_JSON(t *testing.T) {
	results := []CheckResult{
		{Vector: "H2 SETTINGS", Expected: "a", Actual: "a", Pass: true, Severity: "info"},
	}
	actual := DefaultChrome146Reference()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	outputResults(results, actual, true)

	w.Close()
	os.Stdout = old
	buf := make([]byte, 16384)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !json.Valid([]byte(output)) {
		t.Errorf("outputResults JSON mode should produce valid JSON: %q", output)
	}
}

func TestOutputResults_Text(t *testing.T) {
	origNoColor := os.Getenv("NO_COLOR")
	defer os.Setenv("NO_COLOR", origNoColor)
	os.Setenv("NO_COLOR", "1")

	results := []CheckResult{
		{Vector: "H2 SETTINGS", Expected: "a", Actual: "a", Pass: true, Severity: "info"},
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	outputResults(results, nil, false)

	w.Close()
	os.Stdout = old
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "PASS") {
		t.Errorf("outputResults text mode should contain PASS: %q", output)
	}
}

// ──────── compareUint16List additional cases ────────

func TestCompareUint16List_DiffLengthMissingAndExtra(t *testing.T) {
	r := compareUint16List("test", []uint16{1, 3}, []uint16{1, 2}, "info")
	if r.Pass {
		t.Error("should fail")
	}
	if !strings.Contains(r.Note, "missing") || !strings.Contains(r.Note, "extra") {
		t.Errorf("note = %q, want missing and extra", r.Note)
	}
}

// ──────── SaveReference error path ────────

func TestSaveReference_BadPath(t *testing.T) {
	ref := DefaultChrome146Reference()
	// Write to a non-existent deep directory
	err := SaveReference(ref, filepath.Join(t.TempDir(), "a", "b", "c", "ref.json"))
	if err == nil {
		t.Error("expected error for bad path")
	}
}

// ──────── Compare full integration ────────

func TestCompare_FullIntegration(t *testing.T) {
	// Test with everything populated
	ja4t := "abc123"
	expected := &Reference{
		TLS: TLSReference{
			JA4:           "t13d1517h2_abc_def",
			Extensions:    []uint16{0, 23, 51, 13, 43},
			ALPSCodepoint: 17613,
			CipherSuites:  []uint16{0x1301, 0x1302, 0x1303},
			ALPN:          []string{"h2", "http/1.1"},
		},
		H2: H2Reference{
			Settings:          "1:65536;2:0;4:6291456;6:262144",
			WindowUpdate:      15663105,
			Priority:          0,
			PseudoHeaderOrder: "m,a,s,p",
			AkamaiString:      "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		},
		TCP: TCPReference{JA4T: &ja4t},
	}
	actual := &Reference{
		TLS: TLSReference{
			JA4:           "t13d1517h2_abc_def",
			Extensions:    []uint16{0, 23, 51, 13, 43},
			ALPSCodepoint: 17613,
			CipherSuites:  []uint16{0x1301, 0x1302, 0x1303},
			ALPN:          []string{"h2", "http/1.1"},
		},
		H2: H2Reference{
			Settings:          "1:65536;2:0;4:6291456;6:262144",
			WindowUpdate:      15663105,
			Priority:          0,
			PseudoHeaderOrder: "m,a,s,p",
			AkamaiString:      "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		},
		TCP: TCPReference{JA4T: &ja4t},
	}

	results := Compare(actual, expected)
	for _, r := range results {
		if !r.Pass {
			t.Errorf("vector %q should pass: expected=%q actual=%q note=%q", r.Vector, r.Expected, r.Actual, r.Note)
		}
	}
	// Should have many comparison results
	if len(results) < 8 {
		t.Errorf("expected at least 8 results, got %d", len(results))
	}
	// Print them for debugging
	for _, r := range results {
		_ = fmt.Sprintf("%s: %v", r.Vector, r.Pass)
	}
}
