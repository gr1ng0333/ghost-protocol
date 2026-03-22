package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/http2/hpack"
)

// ---------------------------------------------------------------------------
// AnalyzeConfig and RunAnalyze — top-level analyze mode.
// ---------------------------------------------------------------------------

// AnalyzeConfig holds configuration for analyze-mode fingerprint checking.
type AnalyzeConfig struct {
	// PcapFile is the path to the pcap file to analyze.
	PcapFile string

	// ReferenceFile is the optional path to a reference JSON file.
	// If empty, DefaultChrome146Reference() is used.
	ReferenceFile string
}

// RunAnalyze reads a pcap file (or raw TLS record file), extracts fingerprints,
// and compares against the reference. Returns comparison results and the
// extracted fingerprint.
//
// Currently, full pcap reading requires gopacket/libpcap which is not linked.
// As a fallback, if the file starts with a TLS record header (0x16), it is
// parsed directly as a raw ClientHello record. HTTP/2 frames can be appended
// after the TLS record.
func RunAnalyze(cfg AnalyzeConfig) ([]CheckResult, *Reference, error) {
	if cfg.PcapFile == "" {
		return nil, nil, fmt.Errorf("pcap/raw file path is required")
	}

	data, err := os.ReadFile(cfg.PcapFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read file %s: %w", cfg.PcapFile, err)
	}

	// Load reference.
	var expected *Reference
	if cfg.ReferenceFile != "" {
		expected, err = LoadReference(cfg.ReferenceFile)
		if err != nil {
			return nil, nil, fmt.Errorf("load reference: %w", err)
		}
	} else {
		expected = DefaultChrome146Reference()
	}

	// Detect file type.
	if len(data) >= 4 && data[0] == 0xd4 && data[1] == 0xc3 && data[2] == 0xb2 && data[3] == 0xa1 {
		return nil, nil, fmt.Errorf("pcap file detected but gopacket/libpcap is not available — install libpcap-dev and rebuild with gopacket support; alternatively provide a raw TLS record file (starting with 0x16)")
	}
	if len(data) >= 4 && data[0] == 0x0a && data[1] == 0x0d && data[2] == 0x0d && data[3] == 0x0a {
		return nil, nil, fmt.Errorf("pcapng file detected but gopacket/libpcap is not available — install libpcap-dev and rebuild with gopacket support; alternatively provide a raw TLS record file (starting with 0x16)")
	}

	// Try raw TLS record.
	if len(data) < 5 || data[0] != 0x16 {
		return nil, nil, fmt.Errorf("file does not start with TLS handshake record (0x16) or pcap magic; cannot parse")
	}

	chInfo, tlsRecordLen, err := parseClientHelloFromRecord(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ClientHello: %w", err)
	}

	ja4 := ComputeJA4(chInfo)

	// Check for HTTP/2 frames after the TLS record.
	var h2fp *H2Fingerprint
	remaining := data[tlsRecordLen:]
	if len(remaining) > 0 {
		h2fp, err = ParseH2Preface(remaining)
		if err != nil {
			// Non-fatal: we got TLS data at least.
			h2fp = nil
		}
	}

	now := time.Now().UTC()
	actual := &Reference{
		Source:   fmt.Sprintf("Analyzed from %s at %s", cfg.PcapFile, now.Format(time.RFC3339)),
		Captured: now,
		TLS: TLSReference{
			JA4:           ja4,
			Extensions:    chInfo.Extensions,
			ALPSCodepoint: chInfo.ALPSCodepoint,
			CipherSuites:  chInfo.CipherSuites,
			ALPN:          chInfo.ALPN,
		},
		TCP: TCPReference{JA4T: nil},
	}

	if h2fp != nil {
		actual.H2 = H2Reference{
			Settings:          h2fp.Settings,
			WindowUpdate:      h2fp.WindowUpdate,
			Priority:          h2fp.Priority,
			PseudoHeaderOrder: h2fp.PseudoHeaderOrder,
			AkamaiString:      h2fp.AkamaiString,
		}
	}

	results := Compare(actual, expected)
	return results, actual, nil
}

// parseClientHelloFromRecord parses a TLS record starting at data[0] and returns
// the ClientHelloInfo and the total number of bytes consumed (record layer).
func parseClientHelloFromRecord(data []byte) (*ClientHelloInfo, int, error) {
	if len(data) < 5 {
		return nil, 0, fmt.Errorf("data too short for TLS record header")
	}
	if data[0] != 0x16 {
		return nil, 0, fmt.Errorf("not a TLS handshake record (got 0x%02x)", data[0])
	}
	recordLen := int(data[3])<<8 | int(data[4])
	totalLen := 5 + recordLen
	if len(data) < totalLen {
		return nil, 0, fmt.Errorf("TLS record truncated: need %d bytes, have %d", totalLen, len(data))
	}
	info, err := ParseClientHello(data[:totalLen])
	if err != nil {
		return nil, 0, err
	}
	return info, totalLen, nil
}

// ---------------------------------------------------------------------------
// ClientHelloInfo — parsed TLS ClientHello data.
// ---------------------------------------------------------------------------

// ClientHelloInfo holds parsed fingerprint components from a TLS ClientHello.
type ClientHelloInfo struct {
	CipherSuites      []uint16
	Extensions        []uint16
	SignatureAlgos    []uint16
	SupportedVersions []uint16
	ALPN              []string
	SNI               string
	ALPSCodepoint     uint16 // 17513 or 17613, 0 if not present
}

// ---------------------------------------------------------------------------
// ParseClientHello — raw byte parsing.
// ---------------------------------------------------------------------------

// ParseClientHello parses a TLS ClientHello from raw bytes and extracts
// fingerprint components. The input should be a complete TLS record starting
// with the record layer header (ContentType 0x16, Version, Length).
func ParseClientHello(data []byte) (*ClientHelloInfo, error) {
	// Record layer: ContentType(1) + Version(2) + Length(2) = 5 bytes.
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short for TLS record header (%d bytes)", len(data))
	}
	if data[0] != 0x16 {
		return nil, fmt.Errorf("not a handshake record: content type 0x%02x", data[0])
	}
	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return nil, fmt.Errorf("record truncated: declared %d, available %d", recordLen, len(data)-5)
	}

	body := data[5 : 5+recordLen]

	// Handshake header: Type(1) + Length(3) = 4 bytes.
	if len(body) < 4 {
		return nil, fmt.Errorf("data too short for handshake header")
	}
	if body[0] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello: handshake type 0x%02x", body[0])
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	body = body[4:]
	if len(body) < hsLen {
		return nil, fmt.Errorf("ClientHello truncated: declared %d, available %d", hsLen, len(body))
	}
	body = body[:hsLen]

	return parseClientHelloBody(body)
}

func parseClientHelloBody(body []byte) (*ClientHelloInfo, error) {
	info := &ClientHelloInfo{}
	pos := 0

	// Legacy version (2 bytes).
	if pos+2 > len(body) {
		return nil, fmt.Errorf("truncated at legacy version")
	}
	pos += 2

	// Random (32 bytes).
	if pos+32 > len(body) {
		return nil, fmt.Errorf("truncated at random")
	}
	pos += 32

	// Session ID.
	if pos+1 > len(body) {
		return nil, fmt.Errorf("truncated at session ID length")
	}
	sidLen := int(body[pos])
	pos++
	if pos+sidLen > len(body) {
		return nil, fmt.Errorf("truncated at session ID")
	}
	pos += sidLen

	// Cipher suites.
	if pos+2 > len(body) {
		return nil, fmt.Errorf("truncated at cipher suites length")
	}
	csLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	if pos+csLen > len(body) {
		return nil, fmt.Errorf("truncated at cipher suites")
	}
	for i := 0; i+1 < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(body[pos+i : pos+i+2])
		info.CipherSuites = append(info.CipherSuites, cs)
	}
	pos += csLen

	// Compression methods.
	if pos+1 > len(body) {
		return nil, fmt.Errorf("truncated at compression methods length")
	}
	cmLen := int(body[pos])
	pos++
	if pos+cmLen > len(body) {
		return nil, fmt.Errorf("truncated at compression methods")
	}
	pos += cmLen

	// Extensions.
	if pos+2 > len(body) {
		// No extensions — valid but unusual.
		return info, nil
	}
	extTotalLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	if pos+extTotalLen > len(body) {
		return nil, fmt.Errorf("truncated at extensions")
	}
	extData := body[pos : pos+extTotalLen]
	if err := parseExtensions(info, extData); err != nil {
		return nil, fmt.Errorf("parse extensions: %w", err)
	}

	return info, nil
}

func parseExtensions(info *ClientHelloInfo, data []byte) error {
	pos := 0
	for pos+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > len(data) {
			return fmt.Errorf("extension 0x%04x truncated", extType)
		}
		extBody := data[pos : pos+extLen]
		pos += extLen

		info.Extensions = append(info.Extensions, extType)

		switch extType {
		case 0x0000: // SNI
			info.SNI = parseSNI(extBody)
		case 0x0010: // ALPN
			info.ALPN = parseALPN(extBody)
		case 0x002b: // SupportedVersions
			info.SupportedVersions = parseSupportedVersions(extBody)
		case 0x000d: // SignatureAlgorithms
			info.SignatureAlgos = parseSignatureAlgorithms(extBody)
		case 0x4469: // ALPS old (17513)
			info.ALPSCodepoint = 17513
		case 0x44cd: // ALPS new (17613)
			info.ALPSCodepoint = 17613
		}
	}
	return nil
}

func parseSNI(data []byte) string {
	// SNI extension: ListLength(2) + [ Type(1) + NameLength(2) + Name ]
	if len(data) < 5 {
		return ""
	}
	// listLen := int(data[0])<<8 | int(data[1])
	nameType := data[2]
	if nameType != 0 { // 0 = host_name
		return ""
	}
	nameLen := int(data[3])<<8 | int(data[4])
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

func parseALPN(data []byte) []string {
	// ALPN extension: ListLength(2) + [ ProtoLength(1) + Proto ]...
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < listLen {
		return nil
	}
	data = data[:listLen]

	var protos []string
	pos := 0
	for pos < len(data) {
		if pos+1 > len(data) {
			break
		}
		pLen := int(data[pos])
		pos++
		if pos+pLen > len(data) {
			break
		}
		protos = append(protos, string(data[pos:pos+pLen]))
		pos += pLen
	}
	return protos
}

func parseSupportedVersions(data []byte) []uint16 {
	// Client: ListLength(1) + [ Version(2) ]...
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	data = data[1:]
	if len(data) < listLen {
		return nil
	}
	data = data[:listLen]

	var versions []uint16
	for i := 0; i+1 < len(data); i += 2 {
		versions = append(versions, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return versions
}

func parseSignatureAlgorithms(data []byte) []uint16 {
	// ListLength(2) + [ Algorithm(2) ]...
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < listLen {
		return nil
	}
	data = data[:listLen]

	var algos []uint16
	for i := 0; i+1 < len(data); i += 2 {
		algos = append(algos, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return algos
}

// ---------------------------------------------------------------------------
// JA4 computation.
// ---------------------------------------------------------------------------

// IsGREASE reports whether v is a GREASE value.
// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa — both bytes are equal
// and the low nibble of each byte is 0xa.
func IsGREASE(v uint16) bool {
	hi := byte(v >> 8)
	lo := byte(v)
	return hi == lo && (hi&0x0f) == 0x0a
}

// ComputeJA4 computes the JA4 fingerprint string from parsed ClientHello data.
// Format: JA4_a + "_" + JA4_b + "_" + JA4_c
func ComputeJA4(info *ClientHelloInfo) string {
	a := computeJA4a(info)
	b := computeJA4b(info)
	c := computeJA4c(info)
	return a + "_" + b + "_" + c
}

func computeJA4a(info *ClientHelloInfo) string {
	// Protocol: always "t" (TCP/TLS) for our use case.
	proto := "t"

	// TLS version: highest non-GREASE from SupportedVersions, or fallback.
	ver := "00"
	if len(info.SupportedVersions) > 0 {
		var highest uint16
		for _, v := range info.SupportedVersions {
			if !IsGREASE(v) && v > highest {
				highest = v
			}
		}
		ver = mapTLSVersion(highest)
	}

	// SNI: "d" if domain, "i" otherwise.
	sni := "i"
	if info.SNI != "" {
		sni = "d"
	}

	// Cipher count (exclude GREASE).
	cipherCount := 0
	for _, cs := range info.CipherSuites {
		if !IsGREASE(cs) {
			cipherCount++
		}
	}

	// Extension count (exclude GREASE).
	extCount := 0
	for _, ext := range info.Extensions {
		if !IsGREASE(ext) {
			extCount++
		}
	}

	// ALPN: first protocol's first+last char, or "00".
	alpn := "00"
	if len(info.ALPN) > 0 {
		p := info.ALPN[0]
		if len(p) >= 2 {
			alpn = string(p[0]) + string(p[len(p)-1])
		} else if len(p) == 1 {
			alpn = string(p[0]) + string(p[0])
		}
	}

	return fmt.Sprintf("%s%s%s%02d%02d%s", proto, ver, sni, cipherCount, extCount, alpn)
}

func mapTLSVersion(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return "00"
	}
}

func computeJA4b(info *ClientHelloInfo) string {
	// Remove GREASE, encode as 4-char hex, sort, join, hash.
	var hexCiphers []string
	for _, cs := range info.CipherSuites {
		if !IsGREASE(cs) {
			hexCiphers = append(hexCiphers, fmt.Sprintf("%04x", cs))
		}
	}
	sort.Strings(hexCiphers)
	raw := strings.Join(hexCiphers, ",")
	return truncatedSHA256(raw)
}

func computeJA4c(info *ClientHelloInfo) string {
	// Remove GREASE, remove SNI (0x0000) and ALPN (0x0010), encode, sort.
	var hexExts []string
	for _, ext := range info.Extensions {
		if IsGREASE(ext) {
			continue
		}
		if ext == 0x0000 || ext == 0x0010 {
			continue
		}
		hexExts = append(hexExts, fmt.Sprintf("%04x", ext))
	}
	sort.Strings(hexExts)
	raw := strings.Join(hexExts, ",")

	// Append signature algorithms if present.
	if len(info.SignatureAlgos) > 0 {
		var hexAlgos []string
		for _, a := range info.SignatureAlgos {
			hexAlgos = append(hexAlgos, fmt.Sprintf("%04x", a))
		}
		raw += "_" + strings.Join(hexAlgos, ",")
	}

	return truncatedSHA256(raw)
}

func truncatedSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:6])
}

// ---------------------------------------------------------------------------
// H2Fingerprint — HTTP/2 frame parsing.
// ---------------------------------------------------------------------------

// H2Fingerprint holds extracted HTTP/2 fingerprint data.
type H2Fingerprint struct {
	Settings          string // e.g. "1:65536;2:0;4:6291456;6:262144"
	WindowUpdate      uint32
	Priority          int    // 0 if no PRIORITY frames
	PseudoHeaderOrder string // e.g. "m,a,s,p"
	AkamaiString      string // full Akamai fingerprint
}

const (
	h2Magic        = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	h2MagicLen     = 24
	h2FrameHdrLen  = 9
	h2TypeData     = 0x00
	h2TypeHeaders  = 0x01
	h2TypePriority = 0x02
	h2TypeSettings = 0x04
	h2TypeWindowUp = 0x08
)

// ParseH2Preface parses HTTP/2 connection preface and initial frames from raw
// bytes. The input should start with the HTTP/2 connection preface magic or
// directly with the first frame if the magic was already consumed.
func ParseH2Preface(data []byte) (*H2Fingerprint, error) {
	// Skip magic if present.
	if len(data) >= h2MagicLen && string(data[:h2MagicLen]) == h2Magic {
		data = data[h2MagicLen:]
	}

	fp := &H2Fingerprint{}
	var settingsParts []string
	headersFound := false

	for len(data) >= h2FrameHdrLen {
		frameLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
		frameType := data[3]
		// flags := data[4]
		streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF

		data = data[h2FrameHdrLen:]
		if len(data) < frameLen {
			break // incomplete frame
		}
		payload := data[:frameLen]
		data = data[frameLen:]

		switch frameType {
		case h2TypeSettings:
			if streamID == 0 && frameLen%6 == 0 {
				for i := 0; i+6 <= frameLen; i += 6 {
					id := binary.BigEndian.Uint16(payload[i : i+2])
					val := binary.BigEndian.Uint32(payload[i+2 : i+6])
					settingsParts = append(settingsParts, fmt.Sprintf("%d:%d", id, val))
				}
			}
		case h2TypeWindowUp:
			if streamID == 0 && frameLen == 4 {
				fp.WindowUpdate = binary.BigEndian.Uint32(payload[:4]) & 0x7FFFFFFF
			}
		case h2TypePriority:
			fp.Priority++
		case h2TypeHeaders:
			if !headersFound {
				headersFound = true
				fp.PseudoHeaderOrder = decodeH2PseudoHeaders(payload, streamID)
			}
		}
	}

	fp.Settings = strings.Join(settingsParts, ";")
	fp.AkamaiString = fmt.Sprintf("%s|%d|%d|%s",
		fp.Settings, fp.WindowUpdate, fp.Priority, fp.PseudoHeaderOrder)

	return fp, nil
}

var h2PseudoMap = map[string]string{
	":method":    "m",
	":authority": "a",
	":scheme":    "s",
	":path":      "p",
}

func decodeH2PseudoHeaders(payload []byte, streamID uint32) string {
	order := tryHPACKDecodePSH(payload)
	if len(order) == 0 && len(payload) > 5 {
		// May contain priority data (5 bytes) before HPACK block.
		order = tryHPACKDecodePSH(payload[5:])
	}
	return strings.Join(order, ",")
}

func tryHPACKDecodePSH(data []byte) []string {
	var order []string
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if short, ok := h2PseudoMap[f.Name]; ok {
			order = append(order, short)
		}
	})
	_, _ = dec.Write(data)
	return order
}
