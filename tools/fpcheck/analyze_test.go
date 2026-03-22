package main

import (
	"encoding/binary"
	"strings"
	"testing"
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
