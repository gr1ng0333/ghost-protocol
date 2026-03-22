package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
			JA4:        "",   // empty → should skip
			Extensions: nil,  // nil → should skip
			ALPN:       nil,  // nil → should skip
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
