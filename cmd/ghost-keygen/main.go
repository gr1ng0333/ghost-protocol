package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"ghost/internal/auth"
)

func main() {
	// Generate server key pair.
	serverKP, err := auth.GenKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating server key pair: %v\n", err)
		os.Exit(1)
	}

	// Generate client key pair.
	clientKP, err := auth.GenKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating client key pair: %v\n", err)
		os.Exit(1)
	}

	serverPub := hex.EncodeToString(serverKP.Public[:])
	serverPriv := hex.EncodeToString(serverKP.Private[:])
	clientPub := hex.EncodeToString(clientKP.Public[:])
	clientPriv := hex.EncodeToString(clientKP.Private[:])

	fmt.Println("=== Ghost Key Pairs ===")
	fmt.Println()
	fmt.Println("--- Server config (server.yaml) ---")
	fmt.Println("auth:")
	fmt.Printf("  server_public_key: \"%s\"\n", serverPub)
	fmt.Printf("  server_private_key: \"%s\"\n", serverPriv)
	fmt.Printf("  client_public_key: \"%s\"\n", clientPub)
	fmt.Println()
	fmt.Println("--- Client config (client.yaml) ---")
	fmt.Println("auth:")
	fmt.Printf("  server_public_key: \"%s\"\n", serverPub)
	fmt.Printf("  client_private_key: \"%s\"\n", clientPriv)
}
