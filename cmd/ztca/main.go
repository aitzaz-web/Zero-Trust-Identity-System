package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/zero-trust/zt-identity/pkg/ca"
)

const defaultCADir = "ca"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "init":
		runInit()
	case "register":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: ztca register <service>")
			os.Exit(1)
		}
		runRegister(args[0])
	case "issue":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: ztca issue <service>")
			os.Exit(1)
		}
		runIssue(args[0])
	case "revoke":
		runRevoke(args)
	case "status":
		runStatus()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `ztca - Zero-Trust Certificate Authority CLI

Usage:
  ztca init                         Create Root + Intermediate CA, trust bundle
  ztca register <service>           Register service, output bootstrap token
  ztca issue <service>              Issue leaf cert (admin; agents use API)
  ztca revoke <serial>              Revoke cert by serial
  ztca revoke --service <name>      Revoke all certs for service
  ztca status                       List active certs, expirations, revoked
`)
}

func runInit() {
	cfg := ca.Config{BaseDir: defaultCADir}
	if err := cfg.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "init failed: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.CreateEmptyCRL(); err != nil {
		fmt.Fprintf(os.Stderr, "create CRL failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("CA initialized: root, intermediate, trust-bundle, crl in", defaultCADir)
}

func runRegister(service string) {
	// For MVP: generate token; in full flow, RA API does this
	token := "zt-bootstrap-" + randomHex(16)
	fmt.Printf("Service %q registered. Bootstrap token (store securely):\n%s\n", service, token)
	fmt.Printf("SPIFFE ID: spiffe://demo/ns/default/sa/%s\n", service)
}

func runIssue(service string) {
	cfg := ca.Config{BaseDir: defaultCADir}
	spiffeID := fmt.Sprintf("spiffe://demo/ns/default/sa/%s", service)
	certPEM, keyPEM, chainPEM, serial, err := cfg.IssueLeaf(spiffeID, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "issue failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Issued cert for %s, serial %s\n", service, serial)
	// Write to ca/issued/<service>/ for demo (optional local output)
	dir := defaultCADir + "/issued/" + service
	os.MkdirAll(dir, 0700)
	os.WriteFile(dir+"/cert.pem", []byte(certPEM), 0644)
	os.WriteFile(dir+"/key.pem", []byte(keyPEM), 0600)
	os.WriteFile(dir+"/chain.pem", []byte(chainPEM), 0644)
	_ = chainPEM
	_ = keyPEM
	fmt.Printf("Wrote certs to %s/\n", dir)
}

func runRevoke(args []string) {
	// TODO: call RA API to revoke
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ztca revoke <serial> | ztca revoke --service <name>")
		os.Exit(1)
	}
	if args[0] == "--service" && len(args) >= 2 {
		fmt.Printf("Revoked all certs for service %s (RA integration pending)\n", args[1])
		return
	}
	fmt.Printf("Revoked cert serial %s (RA integration pending)\n", args[0])
}

func runStatus() {
	// TODO: call RA API for status
	fmt.Println("Active certs: (RA integration pending)")
	fmt.Println("Revoked: (RA integration pending)")
}

func randomHex(n int) string {
	b := make([]byte, n/2+1)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}
