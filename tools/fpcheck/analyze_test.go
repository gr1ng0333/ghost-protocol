package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// ---------------------------------------------------------------------------
// Test helpers — build raw TLS ClientHello bytes.
// ---------------------------------------------------------------------------

// buildTestClientHello creates a minimal, valid TLS ClientHello record with the
// specified parameters. Returns the complete TLS record (record header + body).
func buildTestClientHello(t *testing.T) []byte {
	t.Helper()

	// ClientHello body.
	var body []byte

	// Legacy version: 0x0303 (TLS 1.2).
	body = append(body, 0x03, 0x03)

	// Random: 32 zero bytes.
	body = append(body, make([]byte, 32)...)

	// Session ID: empty.
	body = append(body, 0x00)

	// Cipher suites: [0x1301, 0x1302, 0x1303].
	ciphers := []uint16{0x1301, 0x1302, 0x1303}
	csBytes := make([]byte, 2+len(ciphers)*2)
	binary.BigEndian.PutUint16(csBytes[0:2], uint16(len(ciphers)*2))
	for i, cs := range ciphers {
		binary.BigEndian.PutUint16(csBytes[2+i*2:4+i*2], cs)
	}
	body = append(body, csBytes...)

	// Compression methods: [0x00].
	body = append(body, 0x01, 0x00)

	// Build extensions.
	var exts []byte

	// Extension: SNI (0x0000) for "example.com".
	sniName := []byte("example.com")
	sniData := make([]byte, 2+1+2+len(sniName))
	binary.BigEndian.PutUint16(sniData[0:2], uint16(1+2+len(sniName))) // list length
	sniData[2] = 0x00                                                  // type: host_name
	binary.BigEndian.PutUint16(sniData[3:5], uint16(len(sniName)))
	copy(sniData[5:], sniName)
	exts = appendExtension(exts, 0x0000, sniData)

	// Extension: SupportedVersions (0x002b) — [0x0304, 0x0303].
	svData := []byte{4, 0x03, 0x04, 0x03, 0x03} // length(1) + 2 versions
	exts = appendExtension(exts, 0x002b, svData)

	// Extension: ALPN (0x0010) — ["h2", "http/1.1"].
	alpnData := buildALPNData([]string{"h2", "http/1.1"})
	exts = appendExtension(exts, 0x0010, alpnData)

	// Extension: SignatureAlgorithms (0x000d) — [0x0403, 0x0503].
	saData := make([]byte, 2+4)
	binary.BigEndian.PutUint16(saData[0:2], 4) // list length
	binary.BigEndian.PutUint16(saData[2:4], 0x0403)
	binary.BigEndian.PutUint16(saData[4:6], 0x0503)
	exts = appendExtension(exts, 0x000d, saData)

	// Extension: ALPS new (0x44cd = 17613).
	exts = appendExtension(exts, 0x44cd, nil)

	// Extensions total length prefix.
	extBlock := make([]byte, 2+len(exts))
	binary.BigEndian.PutUint16(extBlock[0:2], uint16(len(exts)))
	copy(extBlock[2:], exts)
	body = append(body, extBlock...)

	// Handshake header: type=0x01, length=3 bytes.
	hsHeader := make([]byte, 4)
	hsHeader[0] = 0x01
	hsHeader[1] = byte(len(body) >> 16)
	hsHeader[2] = byte(len(body) >> 8)
	hsHeader[3] = byte(len(body))

	// Record layer: type=0x16, version=0x0301, length.
	handshake := append(hsHeader, body...)
	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)

	return record
}

func appendExtension(buf []byte, extType uint16, data []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], extType)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(data)))
	buf = append(buf, hdr...)
	buf = append(buf, data...)
	return buf
}

func buildALPNData(protos []string) []byte {
	var list []byte
	for _, p := range protos {
		list = append(list, byte(len(p)))
		list = append(list, []byte(p)...)
	}
	data := make([]byte, 2+len(list))
	binary.BigEndian.PutUint16(data[0:2], uint16(len(list)))
	copy(data[2:], list)
	return data
}

// buildTestH2Preface builds raw HTTP/2 connection preface bytes with known
// SETTINGS and WINDOW_UPDATE frames.
func buildTestH2Preface(t *testing.T) []byte {
	t.Helper()

	var buf []byte

	// Magic (24 bytes).
	buf = append(buf, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")...)

	// SETTINGS frame: (1, 65536), (2, 0), (4, 6291456), (6, 262144).
	settings := []struct {
		id  uint16
		val uint32
	}{
		{1, 65536}, {2, 0}, {4, 6291456}, {6, 262144},
	}
	settingsPayload := make([]byte, len(settings)*6)
	for i, s := range settings {
		binary.BigEndian.PutUint16(settingsPayload[i*6:i*6+2], s.id)
		binary.BigEndian.PutUint32(settingsPayload[i*6+2:i*6+6], s.val)
	}
	buf = appendH2Frame(buf, h2TypeSettings, 0, 0, settingsPayload)

	// WINDOW_UPDATE frame: increment 15663105.
	wuPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(wuPayload, 15663105)
	buf = appendH2Frame(buf, h2TypeWindowUp, 0, 0, wuPayload)

	return buf
}

func appendH2Frame(buf []byte, ftype byte, flags byte, streamID uint32, payload []byte) []byte {
	hdr := make([]byte, 9)
	l := len(payload)
	hdr[0] = byte(l >> 16)
	hdr[1] = byte(l >> 8)
	hdr[2] = byte(l)
	hdr[3] = ftype
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:9], streamID&0x7FFFFFFF)
	buf = append(buf, hdr...)
	buf = append(buf, payload...)
	return buf
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

func TestParseClientHello(t *testing.T) {
	data := buildTestClientHello(t)

	info, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}

	// Cipher suites.
	wantCiphers := []uint16{0x1301, 0x1302, 0x1303}
	if len(info.CipherSuites) != len(wantCiphers) {
		t.Fatalf("CipherSuites count = %d, want %d", len(info.CipherSuites), len(wantCiphers))
	}
	for i, cs := range wantCiphers {
		if info.CipherSuites[i] != cs {
			t.Errorf("CipherSuites[%d] = 0x%04x, want 0x%04x", i, info.CipherSuites[i], cs)
		}
	}

	// Extensions: 0x0000, 0x002b, 0x0010, 0x000d, 0x44cd.
	wantExts := []uint16{0x0000, 0x002b, 0x0010, 0x000d, 0x44cd}
	if len(info.Extensions) != len(wantExts) {
		t.Fatalf("Extensions count = %d, want %d: got %v", len(info.Extensions), len(wantExts), info.Extensions)
	}
	for i, ext := range wantExts {
		if info.Extensions[i] != ext {
			t.Errorf("Extensions[%d] = 0x%04x, want 0x%04x", i, info.Extensions[i], ext)
		}
	}

	// SNI.
	if info.SNI != "example.com" {
		t.Errorf("SNI = %q, want %q", info.SNI, "example.com")
	}

	// ALPN.
	wantALPN := []string{"h2", "http/1.1"}
	if len(info.ALPN) != len(wantALPN) {
		t.Fatalf("ALPN count = %d, want %d", len(info.ALPN), len(wantALPN))
	}
	for i, a := range wantALPN {
		if info.ALPN[i] != a {
			t.Errorf("ALPN[%d] = %q, want %q", i, info.ALPN[i], a)
		}
	}

	// SupportedVersions.
	wantVersions := []uint16{0x0304, 0x0303}
	if len(info.SupportedVersions) != len(wantVersions) {
		t.Fatalf("SupportedVersions count = %d, want %d", len(info.SupportedVersions), len(wantVersions))
	}
	for i, v := range wantVersions {
		if info.SupportedVersions[i] != v {
			t.Errorf("SupportedVersions[%d] = 0x%04x, want 0x%04x", i, info.SupportedVersions[i], v)
		}
	}

	// SignatureAlgos.
	wantSA := []uint16{0x0403, 0x0503}
	if len(info.SignatureAlgos) != len(wantSA) {
		t.Fatalf("SignatureAlgos count = %d, want %d", len(info.SignatureAlgos), len(wantSA))
	}
	for i, a := range wantSA {
		if info.SignatureAlgos[i] != a {
			t.Errorf("SignatureAlgos[%d] = 0x%04x, want 0x%04x", i, info.SignatureAlgos[i], a)
		}
	}

	// ALPS codepoint.
	if info.ALPSCodepoint != 17613 {
		t.Errorf("ALPSCodepoint = %d, want 17613", info.ALPSCodepoint)
	}
}

func TestComputeJA4(t *testing.T) {
	info := &ClientHelloInfo{
		CipherSuites:      []uint16{0x1301, 0x1302, 0x1303},
		Extensions:        []uint16{0x0000, 0x002b, 0x0010, 0x000d, 0x44cd},
		SupportedVersions: []uint16{0x0304, 0x0303},
		ALPN:              []string{"h2", "http/1.1"},
		SNI:               "example.com",
		SignatureAlgos:    []uint16{0x0403, 0x0503},
	}

	ja4 := ComputeJA4(info)

	// JA4_a: t (TCP) + 13 (TLS 1.3) + d (domain) + 03 (3 ciphers) + 05 (5 exts) + h2
	wantPrefix := "t13d0305h2"
	if !strings.HasPrefix(ja4, wantPrefix) {
		t.Errorf("JA4 prefix = %q, want %q (full: %s)", ja4[:len(wantPrefix)], wantPrefix, ja4)
	}

	// Should have format a_b_c with 12-char hex hashes.
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 should have 3 parts separated by _, got %d: %q", len(parts), ja4)
	}
	if parts[0] != wantPrefix {
		t.Errorf("JA4_a = %q, want %q", parts[0], wantPrefix)
	}
	if len(parts[1]) != 12 {
		t.Errorf("JA4_b length = %d, want 12: %q", len(parts[1]), parts[1])
	}
	if len(parts[2]) != 12 {
		t.Errorf("JA4_c length = %d, want 12: %q", len(parts[2]), parts[2])
	}

	// Verify determinism.
	ja4Again := ComputeJA4(info)
	if ja4 != ja4Again {
		t.Errorf("JA4 not deterministic: %q vs %q", ja4, ja4Again)
	}
}

func TestIsGREASE(t *testing.T) {
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
		0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
		0xcaca, 0xdada, 0xeaea, 0xfafa,
	}
	for _, v := range greaseValues {
		if !IsGREASE(v) {
			t.Errorf("IsGREASE(0x%04x) = false, want true", v)
		}
	}

	nonGrease := []uint16{
		0x0000, 0x0001, 0x1301, 0x1302, 0x1303,
		0xc02b, 0xc02f, 0x44cd, 0x0a0b, 0x1a2a,
	}
	for _, v := range nonGrease {
		if IsGREASE(v) {
			t.Errorf("IsGREASE(0x%04x) = true, want false", v)
		}
	}
}

func TestComputeJA4_GREASEFiltering(t *testing.T) {
	// Same info as TestComputeJA4 but with GREASE values injected.
	infoClean := &ClientHelloInfo{
		CipherSuites:      []uint16{0x1301, 0x1302, 0x1303},
		Extensions:        []uint16{0x0000, 0x002b, 0x0010, 0x000d, 0x44cd},
		SupportedVersions: []uint16{0x0304, 0x0303},
		ALPN:              []string{"h2", "http/1.1"},
		SNI:               "example.com",
		SignatureAlgos:    []uint16{0x0403, 0x0503},
	}

	infoGreasy := &ClientHelloInfo{
		CipherSuites:      []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xfafa},
		Extensions:        []uint16{0x2a2a, 0x0000, 0x002b, 0x0010, 0x000d, 0x44cd, 0xdada},
		SupportedVersions: []uint16{0x3a3a, 0x0304, 0x0303},
		ALPN:              []string{"h2", "http/1.1"},
		SNI:               "example.com",
		SignatureAlgos:    []uint16{0x0403, 0x0503},
	}

	ja4Clean := ComputeJA4(infoClean)
	ja4Greasy := ComputeJA4(infoGreasy)

	if ja4Clean != ja4Greasy {
		t.Errorf("GREASE not properly filtered:\n  clean:  %s\n  greasy: %s", ja4Clean, ja4Greasy)
	}
}

func TestParseH2Preface(t *testing.T) {
	data := buildTestH2Preface(t)

	fp, err := ParseH2Preface(data)
	if err != nil {
		t.Fatalf("ParseH2Preface: %v", err)
	}

	if fp.Settings != "1:65536;2:0;4:6291456;6:262144" {
		t.Errorf("Settings = %q, want %q", fp.Settings, "1:65536;2:0;4:6291456;6:262144")
	}
	if fp.WindowUpdate != 15663105 {
		t.Errorf("WindowUpdate = %d, want 15663105", fp.WindowUpdate)
	}
	if fp.Priority != 0 {
		t.Errorf("Priority = %d, want 0", fp.Priority)
	}

	wantAkamai := "1:65536;2:0;4:6291456;6:262144|15663105|0|"
	if fp.AkamaiString != wantAkamai {
		t.Errorf("AkamaiString = %q, want %q", fp.AkamaiString, wantAkamai)
	}
}

func TestParseH2Preface_WithPriority(t *testing.T) {
	var buf []byte
	buf = append(buf, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")...)

	// Empty SETTINGS frame.
	buf = appendH2Frame(buf, h2TypeSettings, 0, 0, nil)

	// PRIORITY frame on stream 1 (5 bytes: stream_dep(4) + weight(1)).
	priorityPayload := make([]byte, 5)
	buf = appendH2Frame(buf, h2TypePriority, 0, 1, priorityPayload)

	// Another PRIORITY frame.
	buf = appendH2Frame(buf, h2TypePriority, 0, 3, priorityPayload)

	fp, err := ParseH2Preface(buf)
	if err != nil {
		t.Fatalf("ParseH2Preface: %v", err)
	}
	if fp.Priority != 2 {
		t.Errorf("Priority = %d, want 2", fp.Priority)
	}
}

func TestParseClientHello_InvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{0x16, 0x03, 0x01}},
		{"wrong content type", []byte{0x17, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}},
		{"wrong handshake type", []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseClientHello(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestParseClientHello_RoundTrip(t *testing.T) {
	// Build, parse, compute JA4, verify end-to-end.
	data := buildTestClientHello(t)
	info, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}

	ja4 := ComputeJA4(info)
	if ja4 == "" {
		t.Error("JA4 should not be empty")
	}

	// Verify JA4_a components.
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 parts = %d, want 3", len(parts))
	}
	// t=TCP, 13=TLS1.3, d=domain, 03=3 ciphers, 05=5 extensions, h2=ALPN
	if parts[0] != "t13d0305h2" {
		t.Errorf("JA4_a = %q, want %q", parts[0], "t13d0305h2")
	}
}

// ──────── mapTLSVersion ────────

func TestMapTLSVersion(t *testing.T) {
	tests := []struct {
		v    uint16
		want string
	}{
		{0x0304, "13"},
		{0x0303, "12"},
		{0x0302, "11"},
		{0x0301, "10"},
		{0x0300, "00"},
		{0x0000, "00"},
		{0xFFFF, "00"},
	}
	for _, tt := range tests {
		got := mapTLSVersion(tt.v)
		if got != tt.want {
			t.Errorf("mapTLSVersion(0x%04x) = %q, want %q", tt.v, got, tt.want)
		}
	}
}

// ──────── truncatedSHA256 ────────

func TestTruncatedSHA256(t *testing.T) {
	h := truncatedSHA256("hello")
	if len(h) != 12 {
		t.Errorf("truncatedSHA256 length = %d, want 12", len(h))
	}
	// Deterministic
	h2 := truncatedSHA256("hello")
	if h != h2 {
		t.Errorf("truncatedSHA256 not deterministic: %q vs %q", h, h2)
	}
	// Different input → (almost certainly) different hash
	h3 := truncatedSHA256("world")
	if h == h3 {
		t.Error("truncatedSHA256 same for different inputs")
	}
}

// ──────── parseSNI edge cases ────────

func TestParseSNI_EdgeCases(t *testing.T) {
	// Too short
	if got := parseSNI(nil); got != "" {
		t.Errorf("parseSNI(nil) = %q, want empty", got)
	}
	if got := parseSNI([]byte{0, 3}); got != "" {
		t.Errorf("parseSNI(short) = %q, want empty", got)
	}
	// Wrong name type
	data := make([]byte, 10)
	data[2] = 1 // not host_name
	if got := parseSNI(data); got != "" {
		t.Errorf("parseSNI(wrong type) = %q, want empty", got)
	}
	// Name length too long
	data[2] = 0
	data[3] = 0
	data[4] = 100 // claims 100 bytes but only 5 left
	if got := parseSNI(data); got != "" {
		t.Errorf("parseSNI(truncated name) = %q, want empty", got)
	}
}

// ──────── parseALPN edge cases ────────

func TestParseALPN_EdgeCases(t *testing.T) {
	if got := parseALPN(nil); got != nil {
		t.Errorf("parseALPN(nil) = %v, want nil", got)
	}
	if got := parseALPN([]byte{0}); got != nil {
		t.Errorf("parseALPN(1 byte) = %v, want nil", got)
	}
	// List length exceeds data
	if got := parseALPN([]byte{0, 100}); got != nil {
		t.Errorf("parseALPN(truncated) = %v, want nil", got)
	}
}

// ──────── parseSupportedVersions edge cases ────────

func TestParseSupportedVersions_EdgeCases(t *testing.T) {
	if got := parseSupportedVersions(nil); got != nil {
		t.Errorf("parseSupportedVersions(nil) = %v, want nil", got)
	}
	// List length exceeds data
	if got := parseSupportedVersions([]byte{100}); got != nil {
		t.Errorf("parseSupportedVersions(truncated) = %v, want nil", got)
	}
}

// ──────── parseSignatureAlgorithms edge cases ────────

func TestParseSignatureAlgorithms_EdgeCases(t *testing.T) {
	if got := parseSignatureAlgorithms(nil); got != nil {
		t.Errorf("parseSignatureAlgorithms(nil) = %v, want nil", got)
	}
	if got := parseSignatureAlgorithms([]byte{0}); got != nil {
		t.Errorf("parseSignatureAlgorithms(1 byte) = %v, want nil", got)
	}
	// List length exceeds data
	if got := parseSignatureAlgorithms([]byte{0, 100}); got != nil {
		t.Errorf("parseSignatureAlgorithms(truncated) = %v, want nil", got)
	}
}

// ──────── parseClientHelloBody truncation ────────

func TestParseClientHelloBody_Truncation(t *testing.T) {
	// Truncated at legacy version
	_, err := parseClientHelloBody([]byte{0x03})
	if err == nil {
		t.Error("expected error at legacy version")
	}
	// Truncated at random
	body := make([]byte, 2+10) // version + partial random
	_, err = parseClientHelloBody(body)
	if err == nil {
		t.Error("expected error at random")
	}
	// Truncated at session ID length
	body = make([]byte, 34) // version(2) + random(32) but no session ID length
	_, err = parseClientHelloBody(body)
	if err == nil {
		t.Error("expected error at session ID length")
	}
	// Truncated at session ID
	body = make([]byte, 35)
	body[34] = 32 // session ID length = 32, but no data
	_, err = parseClientHelloBody(body)
	if err == nil {
		t.Error("expected error at session ID")
	}
	// Truncated at cipher suites length
	body = make([]byte, 35) // version(2)+random(32)+sid_len(1, value=0)
	body[34] = 0
	_, err = parseClientHelloBody(body)
	if err == nil {
		t.Error("expected error at cipher suites length")
	}
	// Truncated at cipher suites
	body = make([]byte, 37) // +cs_len(2)
	body[34] = 0
	body[35] = 0
	body[36] = 100 // claims 100 bytes
	_, err = parseClientHelloBody(body)
	if err == nil {
		t.Error("expected error at cipher suites")
	}
	// Truncated at compression methods length
	body = make([]byte, 37)
	body[34] = 0
	body[35] = 0
	body[36] = 0 // cs_len = 0
	_, err = parseClientHelloBody(body)
	if err == nil {
		t.Error("expected error at compression methods length")
	}
	// Truncated at compression methods
	body = make([]byte, 38)
	body[34] = 0
	body[35] = 0
	body[36] = 0   // cs_len = 0
	body[37] = 100 // compression methods len = 100
	_, err = parseClientHelloBody(body)
	if err == nil {
		t.Error("expected error at compression methods")
	}
	// No extensions (valid)
	body = make([]byte, 39)
	body[34] = 0 // sid_len = 0
	body[35] = 0 // cs_len high
	body[36] = 0 // cs_len low = 0
	body[37] = 1 // cm_len = 1
	body[38] = 0 // cm = null
	info, err := parseClientHelloBody(body)
	if err != nil {
		t.Fatalf("no extensions should be valid: %v", err)
	}
	if len(info.Extensions) != 0 {
		t.Errorf("expected 0 extensions, got %d", len(info.Extensions))
	}
	// Truncated at extensions
	body = make([]byte, 41)
	body[34] = 0   // sid_len = 0
	body[35] = 0   // cs_len high
	body[36] = 0   // cs_len low = 0
	body[37] = 1   // cm_len = 1
	body[38] = 0   // cm = null
	body[39] = 0   // ext_len high
	body[40] = 100 // ext_len low = 100, but no data
	_, err = parseClientHelloBody(body)
	if err == nil {
		t.Error("expected error at extensions")
	}
}

// ──────── ParseClientHello additional error paths ────────

func TestParseClientHello_RecordTruncated(t *testing.T) {
	// Record says it's 1000 bytes but only 10 available
	data := []byte{0x16, 0x03, 0x01, 0x03, 0xE8, 0x01, 0x00, 0x00, 0x01, 0x00}
	_, err := ParseClientHello(data)
	if err == nil {
		t.Error("expected error for truncated record")
	}
}

func TestParseClientHello_ClientHelloTruncated(t *testing.T) {
	// Valid record header, handshake says 1000 bytes but only 4 available
	hsBody := []byte{0x01, 0x00, 0x03, 0xE8} // type=ClientHello, length=1000
	record := make([]byte, 5+len(hsBody))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(hsBody)))
	copy(record[5:], hsBody)
	_, err := ParseClientHello(record)
	if err == nil {
		t.Error("expected error for truncated ClientHello")
	}
}

// ──────── computeJA4a edge cases ────────

func TestComputeJA4a_NoSNI(t *testing.T) {
	info := &ClientHelloInfo{
		CipherSuites:      []uint16{0x1301},
		Extensions:        []uint16{0x002b},
		SupportedVersions: []uint16{0x0304},
		ALPN:              []string{"h2"},
		SNI:               "", // no SNI → "i"
	}
	ja4 := ComputeJA4(info)
	parts := strings.Split(ja4, "_")
	// Should have "i" for SNI
	if !strings.Contains(parts[0], "i") {
		t.Errorf("JA4_a should contain 'i' for no-SNI: %q", parts[0])
	}
}

func TestComputeJA4a_SingleCharALPN(t *testing.T) {
	info := &ClientHelloInfo{
		CipherSuites:      []uint16{0x1301},
		Extensions:        []uint16{0x002b},
		SupportedVersions: []uint16{0x0304},
		ALPN:              []string{"x"}, // single char
		SNI:               "example.com",
	}
	ja4 := ComputeJA4(info)
	parts := strings.Split(ja4, "_")
	// Single char ALPN → first+first = "xx"
	if !strings.HasSuffix(parts[0], "xx") {
		t.Errorf("JA4_a should end with 'xx' for single-char ALPN: %q", parts[0])
	}
}

func TestComputeJA4a_NoALPN(t *testing.T) {
	info := &ClientHelloInfo{
		CipherSuites:      []uint16{0x1301},
		Extensions:        []uint16{0x002b},
		SupportedVersions: []uint16{0x0304},
		ALPN:              nil, // no ALPN → "00"
		SNI:               "example.com",
	}
	ja4 := ComputeJA4(info)
	parts := strings.Split(ja4, "_")
	if !strings.HasSuffix(parts[0], "00") {
		t.Errorf("JA4_a should end with '00' for no ALPN: %q", parts[0])
	}
}

func TestComputeJA4a_NoSupportedVersions(t *testing.T) {
	info := &ClientHelloInfo{
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{0x002b},
		ALPN:         []string{"h2"},
		SNI:          "example.com",
	}
	ja4 := ComputeJA4(info)
	// ver should be "00" since no SupportedVersions
	if !strings.HasPrefix(ja4, "t00d") {
		t.Errorf("JA4 should start with 't00d' for no SupportedVersions: %q", ja4)
	}
}

// ──────── parseExtensions: extension truncated ────────

func TestParseExtensions_Truncated(t *testing.T) {
	// Extension header says 100 bytes but only 4 available
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:2], 0x0000) // SNI
	binary.BigEndian.PutUint16(data[2:4], 100)    // claims 100 bytes
	info := &ClientHelloInfo{}
	err := parseExtensions(info, data)
	if err == nil {
		t.Error("expected error for truncated extension")
	}
}

// ──────── ParseH2Preface: no magic ────────

func TestParseH2Preface_NoMagic(t *testing.T) {
	// Directly starts with SETTINGS frame (no magic prefix)
	var buf []byte
	settings := []byte{0, 0, 6, h2TypeSettings, 0, 0, 0, 0, 0}
	buf = append(buf, settings...)
	payload := make([]byte, 6)
	binary.BigEndian.PutUint16(payload[0:2], 1)
	binary.BigEndian.PutUint32(payload[2:6], 65536)
	buf = append(buf, payload...)

	fp, err := ParseH2Preface(buf)
	if err != nil {
		t.Fatalf("ParseH2Preface: %v", err)
	}
	if fp.Settings != "1:65536" {
		t.Errorf("Settings = %q, want %q", fp.Settings, "1:65536")
	}
}

func TestParseH2Preface_IncompleteFrame(t *testing.T) {
	var buf []byte
	buf = append(buf, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")...)
	// Frame header says 100 bytes but only 4 available
	hdr := make([]byte, 9)
	hdr[2] = 100 // length = 100
	hdr[3] = h2TypeSettings
	buf = append(buf, hdr...)
	buf = append(buf, make([]byte, 4)...) // only 4 bytes of payload

	fp, err := ParseH2Preface(buf)
	if err != nil {
		t.Fatalf("ParseH2Preface: %v", err)
	}
	// Should handle gracefully (incomplete frame skipped)
	if fp.Settings != "" {
		t.Errorf("Settings should be empty for incomplete frame: %q", fp.Settings)
	}
}

func TestParseH2Preface_SettingsNotDivisibleBy6(t *testing.T) {
	var buf []byte
	buf = append(buf, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")...)
	// SETTINGS with 5-byte payload (not divisible by 6)
	buf = appendH2Frame(buf, h2TypeSettings, 0, 0, make([]byte, 5))

	fp, err := ParseH2Preface(buf)
	if err != nil {
		t.Fatalf("ParseH2Preface: %v", err)
	}
	// Settings should be empty since 5 is not divisible by 6
	if fp.Settings != "" {
		t.Errorf("Settings should be empty for non-divisible-by-6: %q", fp.Settings)
	}
}

func TestParseH2Preface_WindowUpdateNonZeroStream(t *testing.T) {
	var buf []byte
	buf = append(buf, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")...)
	wuPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(wuPayload, 12345)
	// Window update on stream 1 (should be ignored, only stream 0 counts)
	buf = appendH2Frame(buf, h2TypeWindowUp, 0, 1, wuPayload)

	fp, err := ParseH2Preface(buf)
	if err != nil {
		t.Fatalf("ParseH2Preface: %v", err)
	}
	if fp.WindowUpdate != 0 {
		t.Errorf("WindowUpdate should be 0 for non-zero stream: %d", fp.WindowUpdate)
	}
}

func TestParseH2Preface_WindowUpdateWrongLen(t *testing.T) {
	var buf []byte
	buf = append(buf, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")...)
	// Window update with 3-byte payload (should be 4)
	buf = appendH2Frame(buf, h2TypeWindowUp, 0, 0, make([]byte, 3))

	fp, err := ParseH2Preface(buf)
	if err != nil {
		t.Fatalf("ParseH2Preface: %v", err)
	}
	if fp.WindowUpdate != 0 {
		t.Errorf("WindowUpdate should be 0 for wrong length: %d", fp.WindowUpdate)
	}
}

// ──────── decodeH2PseudoHeaders and tryHPACKDecodePSH ────────

func buildHPACKPseudoHeaders(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "example.com"})
	enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
	return buf.Bytes()
}

func TestTryHPACKDecodePSH(t *testing.T) {
	hpackData := buildHPACKPseudoHeaders(t)
	order := tryHPACKDecodePSH(hpackData)
	if len(order) != 4 {
		t.Fatalf("tryHPACKDecodePSH returned %d entries, want 4", len(order))
	}
	want := []string{"m", "a", "s", "p"}
	for i, w := range want {
		if order[i] != w {
			t.Errorf("order[%d] = %q, want %q", i, order[i], w)
		}
	}
}

func TestTryHPACKDecodePSH_Empty(t *testing.T) {
	order := tryHPACKDecodePSH(nil)
	if len(order) != 0 {
		t.Errorf("tryHPACKDecodePSH(nil) returned %d entries, want 0", len(order))
	}
}

func TestDecodeH2PseudoHeaders(t *testing.T) {
	hpackData := buildHPACKPseudoHeaders(t)
	result := decodeH2PseudoHeaders(hpackData, 1)
	if result != "m,a,s,p" {
		t.Errorf("decodeH2PseudoHeaders = %q, want %q", result, "m,a,s,p")
	}
}

func TestDecodeH2PseudoHeaders_WithPriorityPrefix(t *testing.T) {
	// Simulate HEADERS frame with 5-byte priority prefix + HPACK data
	hpackData := buildHPACKPseudoHeaders(t)
	payload := make([]byte, 5+len(hpackData))
	copy(payload[5:], hpackData)

	result := decodeH2PseudoHeaders(payload, 1)
	if result != "m,a,s,p" {
		t.Errorf("decodeH2PseudoHeaders with priority = %q, want %q", result, "m,a,s,p")
	}
}

func TestDecodeH2PseudoHeaders_Garbage(t *testing.T) {
	// Non-HPACK data, short (<=5 bytes) so fallback won't try priority skip
	result := decodeH2PseudoHeaders([]byte{0xFF, 0xFE}, 1)
	if result != "" {
		t.Errorf("decodeH2PseudoHeaders(garbage short) = %q, want empty", result)
	}
}

// ──────── ParseH2Preface with HEADERS frame ────────

func TestParseH2Preface_WithHeaders(t *testing.T) {
	var buf []byte
	buf = append(buf, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")...)

	// Empty SETTINGS
	buf = appendH2Frame(buf, h2TypeSettings, 0, 0, nil)

	// HEADERS frame with HPACK pseudo-headers
	hpackData := buildHPACKPseudoHeaders(t)
	buf = appendH2Frame(buf, h2TypeHeaders, 0x04, 1, hpackData) // 0x04 = END_HEADERS

	fp, err := ParseH2Preface(buf)
	if err != nil {
		t.Fatalf("ParseH2Preface: %v", err)
	}
	if fp.PseudoHeaderOrder != "m,a,s,p" {
		t.Errorf("PseudoHeaderOrder = %q, want %q", fp.PseudoHeaderOrder, "m,a,s,p")
	}
}

// ──────── RunAnalyze with temp file ────────

func TestRunAnalyze_EmptyPcapFile(t *testing.T) {
	_, _, err := RunAnalyze(AnalyzeConfig{PcapFile: ""})
	if err == nil {
		t.Fatal("expected error for empty pcap file")
	}
}

func TestRunAnalyze_MissingFile(t *testing.T) {
	_, _, err := RunAnalyze(AnalyzeConfig{PcapFile: "/nonexistent/file.raw"})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestRunAnalyze_PcapMagic(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.pcap")
	// pcap magic: 0xd4c3b2a1
	os.WriteFile(f, []byte{0xd4, 0xc3, 0xb2, 0xa1, 0, 0, 0, 0}, 0644)
	_, _, err := RunAnalyze(AnalyzeConfig{PcapFile: f})
	if err == nil || !strings.Contains(err.Error(), "pcap file detected") {
		t.Errorf("expected pcap detection error, got %v", err)
	}
}

func TestRunAnalyze_PcapngMagic(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.pcapng")
	// pcapng magic: 0x0a0d0d0a
	os.WriteFile(f, []byte{0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0}, 0644)
	_, _, err := RunAnalyze(AnalyzeConfig{PcapFile: f})
	if err == nil || !strings.Contains(err.Error(), "pcapng file detected") {
		t.Errorf("expected pcapng detection error, got %v", err)
	}
}

func TestRunAnalyze_NotTLSRecord(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.raw")
	os.WriteFile(f, []byte{0x42, 0x42, 0x42, 0x42, 0x42}, 0644)
	_, _, err := RunAnalyze(AnalyzeConfig{PcapFile: f})
	if err == nil || !strings.Contains(err.Error(), "does not start with TLS") {
		t.Errorf("expected TLS detection error, got %v", err)
	}
}

func TestRunAnalyze_TooShort(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.raw")
	os.WriteFile(f, []byte{0x16, 0x03}, 0644)
	_, _, err := RunAnalyze(AnalyzeConfig{PcapFile: f})
	if err == nil {
		t.Fatal("expected error for too short data")
	}
}

func TestRunAnalyze_RawTLSRecord(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.raw")

	tlsRecord := buildTestClientHello(t)
	os.WriteFile(f, tlsRecord, 0644)

	results, actual, err := RunAnalyze(AnalyzeConfig{PcapFile: f})
	if err != nil {
		t.Fatalf("RunAnalyze: %v", err)
	}
	if actual == nil {
		t.Fatal("actual is nil")
	}
	if actual.TLS.JA4 == "" {
		t.Error("JA4 should not be empty")
	}
	if len(actual.TLS.CipherSuites) != 3 {
		t.Errorf("CipherSuites = %d, want 3", len(actual.TLS.CipherSuites))
	}
	if len(results) == 0 {
		t.Error("expected comparison results")
	}
}

func TestRunAnalyze_TLSPlusH2(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.raw")

	tlsRecord := buildTestClientHello(t)
	h2Data := buildTestH2Preface(t)
	combined := append(tlsRecord, h2Data...)
	os.WriteFile(f, combined, 0644)

	results, actual, err := RunAnalyze(AnalyzeConfig{PcapFile: f})
	if err != nil {
		t.Fatalf("RunAnalyze: %v", err)
	}
	if actual.H2.Settings == "" {
		t.Error("H2 settings should not be empty")
	}
	if actual.H2.WindowUpdate != 15663105 {
		t.Errorf("H2 WindowUpdate = %d, want 15663105", actual.H2.WindowUpdate)
	}
	// Should have comparison results
	if len(results) == 0 {
		t.Error("expected comparison results")
	}
}

func TestRunAnalyze_WithReferenceFile(t *testing.T) {
	dir := t.TempDir()

	// Write reference
	refPath := filepath.Join(dir, "ref.json")
	ref := DefaultChrome146Reference()
	if err := SaveReference(ref, refPath); err != nil {
		t.Fatalf("SaveReference: %v", err)
	}

	// Write TLS record
	rawPath := filepath.Join(dir, "test.raw")
	os.WriteFile(rawPath, buildTestClientHello(t), 0644)

	results, actual, err := RunAnalyze(AnalyzeConfig{PcapFile: rawPath, ReferenceFile: refPath})
	if err != nil {
		t.Fatalf("RunAnalyze: %v", err)
	}
	if actual == nil {
		t.Fatal("actual is nil")
	}
	if len(results) == 0 {
		t.Error("expected comparison results")
	}
}

func TestRunAnalyze_BadReferenceFile(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "test.raw")
	os.WriteFile(rawPath, buildTestClientHello(t), 0644)

	_, _, err := RunAnalyze(AnalyzeConfig{PcapFile: rawPath, ReferenceFile: "/nonexistent"})
	if err == nil || !strings.Contains(err.Error(), "load reference") {
		t.Errorf("expected load reference error, got %v", err)
	}
}

func TestRunAnalyze_BadTLSParse(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.raw")
	// Valid TLS record header but wrong handshake type
	os.WriteFile(f, []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}, 0644)
	_, _, err := RunAnalyze(AnalyzeConfig{PcapFile: f})
	if err == nil || !strings.Contains(err.Error(), "parse ClientHello") {
		t.Errorf("expected parse error, got %v", err)
	}
}

func TestRunAnalyze_BadH2Appended(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.raw")

	tlsRecord := buildTestClientHello(t)
	// Append garbage after TLS record (not valid H2)
	garbage := []byte{0xFF, 0xFE, 0xFD, 0xFC}
	os.WriteFile(f, append(tlsRecord, garbage...), 0644)

	// Should succeed — bad H2 is non-fatal
	_, actual, err := RunAnalyze(AnalyzeConfig{PcapFile: f})
	if err != nil {
		t.Fatalf("RunAnalyze: %v", err)
	}
	// H2 fields should be empty since parse failed
	if actual.H2.Settings != "" {
		t.Errorf("H2 settings should be empty for bad H2: %q", actual.H2.Settings)
	}
}

// ──────── parseClientHelloFromRecord direct tests ────────

func TestParseClientHelloFromRecord_Valid(t *testing.T) {
	data := buildTestClientHello(t)
	info, consumed, err := parseClientHelloFromRecord(data)
	if err != nil {
		t.Fatalf("parseClientHelloFromRecord: %v", err)
	}
	if info == nil {
		t.Fatal("info is nil")
	}
	if consumed != len(data) {
		t.Errorf("consumed = %d, want %d", consumed, len(data))
	}
}

func TestParseClientHelloFromRecord_TooShort(t *testing.T) {
	_, _, err := parseClientHelloFromRecord([]byte{0x16, 0x03})
	if err == nil {
		t.Error("expected error for too short data")
	}
}

func TestParseClientHelloFromRecord_NotHandshake(t *testing.T) {
	_, _, err := parseClientHelloFromRecord([]byte{0x17, 0x03, 0x01, 0x00, 0x01})
	if err == nil {
		t.Error("expected error for non-handshake")
	}
}

func TestParseClientHelloFromRecord_Truncated(t *testing.T) {
	// Record says 1000 bytes but only 5 available
	data := []byte{0x16, 0x03, 0x01, 0x03, 0xE8}
	_, _, err := parseClientHelloFromRecord(data)
	if err == nil {
		t.Error("expected error for truncated record")
	}
}

// ──────── ALPS old codepoint ────────

func TestParseClientHello_ALPSOld(t *testing.T) {
	// Build a ClientHello with ALPS old (0x4469 = 17513) instead of new
	var body []byte
	body = append(body, 0x03, 0x03)             // version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session ID len = 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites: 1 (TLS_AES_128_GCM_SHA256)
	body = append(body, 0x01, 0x00)             // compression: 1 method (null)

	var exts []byte
	exts = appendExtension(exts, 0x4469, nil) // ALPS old
	extBlock := make([]byte, 2+len(exts))
	binary.BigEndian.PutUint16(extBlock[0:2], uint16(len(exts)))
	copy(extBlock[2:], exts)
	body = append(body, extBlock...)

	// Wrap in handshake + record
	hsHeader := make([]byte, 4)
	hsHeader[0] = 0x01
	hsHeader[1] = byte(len(body) >> 16)
	hsHeader[2] = byte(len(body) >> 8)
	hsHeader[3] = byte(len(body))
	handshake := append(hsHeader, body...)
	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)

	info, err := ParseClientHello(record)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if info.ALPSCodepoint != 17513 {
		t.Errorf("ALPSCodepoint = %d, want 17513", info.ALPSCodepoint)
	}
}

// ──────── ParseH2Preface: SETTINGS on non-zero stream ────────

func TestParseH2Preface_SettingsNonZeroStream(t *testing.T) {
	var buf []byte
	buf = append(buf, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")...)
	payload := make([]byte, 6)
	binary.BigEndian.PutUint16(payload[0:2], 1)
	binary.BigEndian.PutUint32(payload[2:6], 65536)
	buf = appendH2Frame(buf, h2TypeSettings, 0, 1, payload) // stream 1, should be ignored

	fp, err := ParseH2Preface(buf)
	if err != nil {
		t.Fatalf("ParseH2Preface: %v", err)
	}
	if fp.Settings != "" {
		t.Errorf("Settings should be empty for non-zero stream: %q", fp.Settings)
	}
}
