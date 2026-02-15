package ca

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInit(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{BaseDir: dir}
	if err := cfg.Init(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"root.key", "root.crt", "intermediate.key", "intermediate.crt", "trust-bundle.pem"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
}

func TestIssueLeaf(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{BaseDir: dir}
	if err := cfg.Init(); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, chainPEM, serial, err := cfg.IssueLeaf("spiffe://demo/ns/default/sa/test", 0)
	if err != nil {
		t.Fatal(err)
	}
	if serial == "" || certPEM == "" || keyPEM == "" || chainPEM == "" {
		t.Error("empty output")
	}
}
