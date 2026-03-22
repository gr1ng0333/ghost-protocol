package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	btls "github.com/bogdanfinn/utls"
	utls "github.com/refraction-networking/utls"
)

func main() {
	log.SetFlags(0)

	const (
		targetHost = "tls.peet.ws"
		targetAddr = "tls.peet.ws:443"
		targetURL  = "https://tls.peet.ws/api/all"
	)

	// Configure HTTP/2 transport with Chrome SETTINGS
	h2Transport := &http2.Transport{
		DialTLS: func(network, addr string, _ *btls.Config) (net.Conn, error) {
			return dialUTLS(network, addr)
		},
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingEnablePush:        0,
			http2.SettingInitialWindowSize: 6291456,
			http2.SettingMaxHeaderListSize: 262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		ConnectionFlow:    15663105,
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
	}

	client := &http.Client{Transport: h2Transport}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		log.Fatalf("create request: %v", err)
	}

	// Set Chrome-like headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-Ch-Ua", `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header[http.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
	req.Header[http.HeaderOrderKey] = []string{
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"upgrade-insecure-requests", "user-agent", "accept",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
		"accept-encoding", "accept-language",
	}

	fmt.Println("=== Ghost Fingerprint Test ===")
	fmt.Printf("[*] Target: %s\n", targetURL)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("[!] Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("[!] Read body: %v", err)
	}

	fmt.Printf("[+] HTTP status: %s\n", resp.Status)
	fmt.Printf("[+] Protocol: %s\n\n", resp.Proto)

	// Parse and display fingerprint data
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Printf("Raw response:\n%s\n", body)
		os.Exit(0)
	}

	pretty, _ := json.MarshalIndent(result, "", "  ")
	fmt.Printf("=== Full Response ===\n%s\n\n", pretty)

	// Highlight key fingerprint values from nested structure
	fmt.Println("=== Key Fingerprint Values ===")
	if tlsInfo := getMap(result, "tls"); tlsInfo != nil {
		printField(tlsInfo, "ja4", "JA4 Hash")
		printField(tlsInfo, "ja4_r", "JA4_r")
		printField(tlsInfo, "ja3", "JA3 String")
		printField(tlsInfo, "ja3_hash", "JA3 MD5")
		printField(tlsInfo, "peetprint_hash", "Peetprint Hash")
	}

	// Print HTTP/2 details
	if h2 := getMap(result, "http2"); h2 != nil {
		fmt.Println("\n=== HTTP/2 Details ===")
		printField(h2, "akamai_fingerprint", "Akamai H2 Fingerprint")
		printField(h2, "akamai_fingerprint_hash", "Akamai H2 FP Hash")
		if frames := getSlice(h2, "sent_frames"); frames != nil {
			for _, f := range frames {
				fm, ok := f.(map[string]interface{})
				if !ok {
					continue
				}
				switch fm["frame_type"] {
				case "SETTINGS":
					if settings := getSlice(fm, "settings"); settings != nil {
						fmt.Println("SETTINGS:")
						for _, s := range settings {
							fmt.Printf("  %v\n", s)
						}
					}
				case "WINDOW_UPDATE":
					if inc, ok := fm["increment"].(float64); ok {
						fmt.Printf("WINDOW_UPDATE: %d\n", int64(inc))
					} else {
						fmt.Printf("WINDOW_UPDATE: %v\n", fm["increment"])
					}
				case "HEADERS":
					if headers := getSlice(fm, "headers"); headers != nil {
						fmt.Println("Pseudo-header order (from HEADERS frame):")
						for _, h := range headers {
							s, _ := h.(string)
							if len(s) > 0 && s[0] == ':' {
								fmt.Printf("  %s\n", s)
							}
						}
					}
				}
			}
		}
	}
}

func dialUTLS(network, addr string) (net.Conn, error) {
	rawConn, err := net.DialTimeout(network, addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP dial %s: %w", addr, err)
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("split host/port %s: %w", addr, err)
	}

	uconn := utls.UClient(rawConn, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
	if err := uconn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("uTLS handshake: %w", err)
	}

	state := uconn.ConnectionState()
	fmt.Printf("[+] TLS handshake OK (version: 0x%04x, ALPN: %s)\n", state.Version, state.NegotiatedProtocol)

	if state.NegotiatedProtocol != "h2" {
		uconn.Close()
		return nil, fmt.Errorf("expected ALPN h2, got %q", state.NegotiatedProtocol)
	}

	return uconn, nil
}

func printField(m map[string]interface{}, key, label string) {
	if v, ok := m[key]; ok {
		fmt.Printf("%-25s %v\n", label+":", v)
	}
}

func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key]; ok {
		if mm, ok := v.(map[string]interface{}); ok {
			return mm
		}
	}
	return nil
}

func getSlice(m map[string]interface{}, key string) []interface{} {
	if v, ok := m[key]; ok {
		if s, ok := v.([]interface{}); ok {
			return s
		}
	}
	return nil
}
