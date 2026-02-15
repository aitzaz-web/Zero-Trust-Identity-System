package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var (
	raURL   = getEnv("RA_URL", "http://ra:8443")
	certDir = getEnv("CERT_DIR", "/certs")
)

func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	serviceID := os.Getenv("SERVICE_ID")
	token := os.Getenv("BOOTSTRAP_TOKEN")
	if serviceID == "" || token == "" {
		fmt.Fprintf(os.Stderr, "SERVICE_ID and BOOTSTRAP_TOKEN required\n")
		os.Exit(1)
	}

	// Register first if needed (agent uses token to issue)
	resp, err := fetchCert(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch cert failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "issue failed: %s: %s\n", resp.Status, string(body))
		os.Exit(1)
	}

	var result struct {
		CertPEM  string `json:"cert_pem"`
		KeyPEM   string `json:"key_pem"`
		ChainPEM string `json:"chain_pem"`
		Serial   string `json:"serial"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Fprintf(os.Stderr, "decode failed: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(certDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir failed: %v\n", err)
		os.Exit(1)
	}
	writeFile(filepath.Join(certDir, "cert.pem"), result.CertPEM, 0644)
	writeFile(filepath.Join(certDir, "key.pem"), result.KeyPEM, 0600)
	writeFile(filepath.Join(certDir, "chain.pem"), result.ChainPEM, 0644)

	fmt.Printf("Cert issued for %s, serial %s\n", serviceID, result.Serial)

	// TODO: rotation loop (renew at 2/3 lifetime)
	select {}
}

func fetchCert(token string) (*http.Response, error) {
	req, _ := http.NewRequest("POST", raURL+"/v1/issue", bytes.NewReader(nil))
	req.Header.Set("X-Bootstrap-Token", token)
	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

func writeFile(path, content string, mode os.FileMode) {
	// Atomic write: temp + rename
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
		os.Exit(1)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(os.Stderr, "rename %s: %v\n", path, err)
		os.Exit(1)
	}
}
