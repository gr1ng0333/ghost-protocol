package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ──────── runBaseline ────────

func TestRunBaseline_SaveToFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "baseline.json")

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runBaseline(outFile, false)

	w.Close()
	os.Stdout = old
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "Reference saved") {
		t.Errorf("output = %q, want 'Reference saved'", output)
	}

	// Verify file was written
	if _, err := os.Stat(outFile); os.IsNotExist(err) {
		t.Error("baseline file was not written")
	}
}

func TestRunBaseline_JSONOutput(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runBaseline("", true)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "Chrome 146") {
		t.Errorf("output should contain 'Chrome 146': %q", output[:min(len(output), 200)])
	}
}

func TestRunBaseline_TextOutput(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runBaseline("", false)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "Source:") {
		t.Errorf("output should contain 'Source:': %q", output[:min(len(output), 200)])
	}
	if !strings.Contains(output, "H2 Settings:") {
		t.Errorf("output should contain 'H2 Settings:': %q", output[:min(len(output), 200)])
	}
}

// ──────── runAnalyze happy path ────────

func TestRunAnalyze_HappyPath(t *testing.T) {
	origNoColor := os.Getenv("NO_COLOR")
	defer os.Setenv("NO_COLOR", origNoColor)
	os.Setenv("NO_COLOR", "1")

	dir := t.TempDir()
	pcapFile := filepath.Join(dir, "test.raw")

	// Build test TLS ClientHello record
	tlsRecord := buildTestHelloForMain(t)
	os.WriteFile(pcapFile, tlsRecord, 0644)

	// Create an empty reference so no critical failures trigger os.Exit
	refPath := filepath.Join(dir, "ref.json")
	ref := &Reference{}
	SaveReference(ref, refPath)

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runAnalyze(pcapFile, refPath, false)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "Ghost Fingerprint Check") {
		t.Errorf("output should contain header: %q", output[:min(len(output), 200)])
	}
}

func TestRunAnalyze_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	pcapFile := filepath.Join(dir, "test.raw")

	tlsRecord := buildTestHelloForMain(t)
	os.WriteFile(pcapFile, tlsRecord, 0644)

	// Create an empty reference so no critical failures trigger os.Exit
	refPath := filepath.Join(dir, "ref.json")
	ref := &Reference{}
	SaveReference(ref, refPath)

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runAnalyze(pcapFile, refPath, true)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "results") {
		t.Errorf("JSON output should contain 'results': %q", output[:min(len(output), 200)])
	}
}

// buildTestHelloForMain creates a minimal TLS ClientHello record (duplicated from analyze_test.go)
// because test helpers are not shared across test files in the same package without more work.
func buildTestHelloForMain(t *testing.T) []byte {
	t.Helper()

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)

	ciphers := []uint16{0x1301, 0x1302, 0x1303}
	csBytes := make([]byte, 2+len(ciphers)*2)
	binary.BigEndian.PutUint16(csBytes[0:2], uint16(len(ciphers)*2))
	for i, cs := range ciphers {
		binary.BigEndian.PutUint16(csBytes[2+i*2:4+i*2], cs)
	}
	body = append(body, csBytes...)
	body = append(body, 0x01, 0x00)

	// Extensions: SNI + SupportedVersions
	var exts []byte
	sniName := []byte("example.com")
	sniData := make([]byte, 2+1+2+len(sniName))
	binary.BigEndian.PutUint16(sniData[0:2], uint16(1+2+len(sniName)))
	sniData[2] = 0x00
	binary.BigEndian.PutUint16(sniData[3:5], uint16(len(sniName)))
	copy(sniData[5:], sniName)
	exts = appendExt(exts, 0x0000, sniData)

	svData := []byte{4, 0x03, 0x04, 0x03, 0x03}
	exts = appendExt(exts, 0x002b, svData)

	extBlock := make([]byte, 2+len(exts))
	binary.BigEndian.PutUint16(extBlock[0:2], uint16(len(exts)))
	copy(extBlock[2:], exts)
	body = append(body, extBlock...)

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
	return record
}

func appendExt(buf []byte, extType uint16, data []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], extType)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(data)))
	buf = append(buf, hdr...)
	buf = append(buf, data...)
	return buf
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
