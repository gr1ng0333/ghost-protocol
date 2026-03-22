package main

import (
	"testing"
)

// Sample JSON response mimicking tls.peet.ws/api/all output.
const sampleEchoJSON = `{
  "ip": "1.2.3.4:12345",
  "http_version": "h2",
  "tls": {
    "ciphers": [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
      "TLS_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_RSA_WITH_AES_128_CBC_SHA",
      "TLS_RSA_WITH_AES_256_CBC_SHA"
    ],
    "extensions": [
      {"name": "server_name (0)"},
      {"name": "extended_master_secret (23)"},
      {"name": "renegotiation_info (65281)"},
      {"name": "supported_groups (10)"},
      {"name": "ec_point_formats (11)"},
      {"name": "session_ticket (35)"},
      {"name": "application_layer_protocol_negotiation (16)"},
      {"name": "status_request (5)"},
      {"name": "signature_algorithms (13)"},
      {"name": "signed_certificate_timestamp (18)"},
      {"name": "key_share (51)"},
      {"name": "psk_key_exchange_modes (45)"},
      {"name": "supported_versions (43)"},
      {"name": "compress_certificate (27)"},
      {"name": "application_settings (17613)"},
      {"name": "padding (21)"}
    ],
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613-21,29-23-24,0",
    "ja3_hash": "cd08e31494f9531f560d64c695473da9",
    "ja4": "t13d1517h2_8daaf6152771_e5627efa2ab1",
    "ja4_r": "t13d1517h2_002f,009c,..._0005,000a,...",
    "tls_version_record": "0x0301",
    "tls_version_negotiated": "0x0303"
  },
  "http2": {
    "akamai_fingerprint": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    "akamai_fingerprint_hash": "abc123",
    "sent_frames": [
      {
        "frame_type": "SETTINGS",
        "length": 24,
        "settings": ["HEADER_TABLE_SIZE = 65536", "ENABLE_PUSH = 0", "INITIAL_WINDOW_SIZE = 6291456", "MAX_HEADER_LIST_SIZE = 262144"],
        "stream_id": 0
      },
      {
        "frame_type": "WINDOW_UPDATE",
        "increment": 15663105,
        "length": 4,
        "stream_id": 0
      },
      {
        "frame_type": "HEADERS",
        "headers": [":method: GET", ":authority: tls.peet.ws", ":scheme: https", ":path: /api/all"],
        "flags": ["END_HEADERS"],
        "stream_id": 1
      }
    ]
  }
}`

func TestParseEchoResponse(t *testing.T) {
	ref, err := parseEchoResponse([]byte(sampleEchoJSON))
	if err != nil {
		t.Fatalf("parseEchoResponse: %v", err)
	}

	// TLS JA4.
	if ref.TLS.JA4 != "t13d1517h2_8daaf6152771_e5627efa2ab1" {
		t.Errorf("JA4 = %q, want %q", ref.TLS.JA4, "t13d1517h2_8daaf6152771_e5627efa2ab1")
	}

	// Extensions should have 16 entries.
	if len(ref.TLS.Extensions) != 16 {
		t.Errorf("Extensions count = %d, want 16", len(ref.TLS.Extensions))
	}

	// First extension should be 0 (server_name).
	if len(ref.TLS.Extensions) > 0 && ref.TLS.Extensions[0] != 0 {
		t.Errorf("Extensions[0] = %d, want 0", ref.TLS.Extensions[0])
	}

	// ALPS codepoint.
	if ref.TLS.ALPSCodepoint != 17613 {
		t.Errorf("ALPSCodepoint = %d, want 17613", ref.TLS.ALPSCodepoint)
	}

	// Cipher suites — 15 known ciphers, no GREASE.
	if len(ref.TLS.CipherSuites) != 15 {
		t.Errorf("CipherSuites count = %d, want 15", len(ref.TLS.CipherSuites))
	}
	if len(ref.TLS.CipherSuites) > 0 && ref.TLS.CipherSuites[0] != 0x1301 {
		t.Errorf("CipherSuites[0] = 0x%04x, want 0x1301", ref.TLS.CipherSuites[0])
	}

	// ALPN.
	if len(ref.TLS.ALPN) != 2 || ref.TLS.ALPN[0] != "h2" {
		t.Errorf("ALPN = %v, want [h2, http/1.1]", ref.TLS.ALPN)
	}

	// H2 fields from Akamai string.
	if ref.H2.Settings != "1:65536;2:0;4:6291456;6:262144" {
		t.Errorf("Settings = %q, want %q", ref.H2.Settings, "1:65536;2:0;4:6291456;6:262144")
	}
	if ref.H2.WindowUpdate != 15663105 {
		t.Errorf("WindowUpdate = %d, want 15663105", ref.H2.WindowUpdate)
	}
	if ref.H2.Priority != 0 {
		t.Errorf("Priority = %d, want 0", ref.H2.Priority)
	}
	if ref.H2.PseudoHeaderOrder != "m,a,s,p" {
		t.Errorf("PseudoHeaderOrder = %q, want %q", ref.H2.PseudoHeaderOrder, "m,a,s,p")
	}
	if ref.H2.AkamaiString != "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p" {
		t.Errorf("AkamaiString = %q", ref.H2.AkamaiString)
	}
}

func TestParseEchoResponse_CompareAgainstChrome146(t *testing.T) {
	actual, err := parseEchoResponse([]byte(sampleEchoJSON))
	if err != nil {
		t.Fatalf("parseEchoResponse: %v", err)
	}

	expected := DefaultChrome146Reference()
	results := Compare(actual, expected)

	// H2 fields should all pass since the sample matches Chrome 146.
	for _, r := range results {
		if r.Vector == "H2 SETTINGS" && !r.Pass {
			t.Errorf("H2 SETTINGS should pass: actual=%q expected=%q", r.Actual, r.Expected)
		}
		if r.Vector == "H2 WINDOW_UPDATE" && !r.Pass {
			t.Errorf("H2 WINDOW_UPDATE should pass: actual=%q expected=%q", r.Actual, r.Expected)
		}
		if r.Vector == "H2 PSH order" && !r.Pass {
			t.Errorf("H2 PSH order should pass: actual=%q expected=%q", r.Actual, r.Expected)
		}
		if r.Vector == "TLS ALPS codepoint" && !r.Pass {
			t.Errorf("TLS ALPS codepoint should pass: actual=%q expected=%q", r.Actual, r.Expected)
		}
	}
}

func TestParseExtensionIDs(t *testing.T) {
	exts := []echoExtension{
		{Name: "server_name (0)"},
		{Name: "application_settings (17613)"},
		{Name: "unknown_extension"},
		{Name: "padding (21)"},
	}

	ids := parseExtensionIDs(exts)
	if len(ids) != 3 {
		t.Fatalf("parseExtensionIDs returned %d IDs, want 3", len(ids))
	}
	if ids[0] != 0 {
		t.Errorf("ids[0] = %d, want 0", ids[0])
	}
	if ids[1] != 17613 {
		t.Errorf("ids[1] = %d, want 17613", ids[1])
	}
	if ids[2] != 21 {
		t.Errorf("ids[2] = %d, want 21", ids[2])
	}
}

func TestDetectALPSCodepoint(t *testing.T) {
	tests := []struct {
		name string
		ids  []uint16
		want uint16
	}{
		{"new ALPS", []uint16{0, 23, 17613, 21}, 17613},
		{"old ALPS", []uint16{0, 23, 17513, 21}, 17513},
		{"no ALPS", []uint16{0, 23, 51, 21}, 0},
		{"empty", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectALPSCodepoint(tt.ids)
			if got != tt.want {
				t.Errorf("detectALPSCodepoint = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseCipherSuites(t *testing.T) {
	names := []string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_CHACHA20_POLY1305_SHA256",
		"UNKNOWN_CIPHER",
		"TLS_GREASE_0xdada",
	}

	ids := parseCipherSuites(names)
	// UNKNOWN_CIPHER skipped, GREASE skipped → 2 results.
	if len(ids) != 2 {
		t.Fatalf("parseCipherSuites returned %d IDs, want 2", len(ids))
	}
	if ids[0] != 0x1301 {
		t.Errorf("ids[0] = 0x%04x, want 0x1301", ids[0])
	}
	if ids[1] != 0x1303 {
		t.Errorf("ids[1] = 0x%04x, want 0x1303", ids[1])
	}
}

func TestParseAkamaiFingerprint(t *testing.T) {
	fp := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	h2 := parseAkamaiFingerprint(fp)

	if h2.Settings != "1:65536;2:0;4:6291456;6:262144" {
		t.Errorf("Settings = %q", h2.Settings)
	}
	if h2.WindowUpdate != 15663105 {
		t.Errorf("WindowUpdate = %d", h2.WindowUpdate)
	}
	if h2.Priority != 0 {
		t.Errorf("Priority = %d", h2.Priority)
	}
	if h2.PseudoHeaderOrder != "m,a,s,p" {
		t.Errorf("PseudoHeaderOrder = %q", h2.PseudoHeaderOrder)
	}
	if h2.AkamaiString != fp {
		t.Errorf("AkamaiString = %q", h2.AkamaiString)
	}
}

func TestParseAkamaiFingerprint_Empty(t *testing.T) {
	h2 := parseAkamaiFingerprint("")
	if h2.Settings != "" || h2.WindowUpdate != 0 || h2.PseudoHeaderOrder != "" {
		t.Errorf("expected zero values for empty fingerprint, got %+v", h2)
	}
}

func TestResolveUTLSPreset(t *testing.T) {
	// Ensure known presets resolve without panic.
	presets := []string{
		"HelloChrome_Auto",
		"HelloChrome_120",
		"HelloFirefox_Auto",
		"UnknownPreset",
	}
	for _, name := range presets {
		p := resolveUTLSPreset(name)
		if p == nil {
			t.Errorf("resolveUTLSPreset(%q) returned nil", name)
		}
	}
}
