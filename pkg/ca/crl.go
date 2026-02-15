package ca

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)


// CreateEmptyCRL creates an empty CRL for the Intermediate CA.
func (c *Config) CreateEmptyCRL() error {
	interCertPEM, err := os.ReadFile(filepath.Join(c.BaseDir, "intermediate.crt"))
	if err != nil {
		return err
	}
	interKeyPEM, err := os.ReadFile(filepath.Join(c.BaseDir, "intermediate.key"))
	if err != nil {
		return err
	}
	interCertBlock, _ := pem.Decode(interCertPEM)
	interCert, err := x509.ParseCertificate(interCertBlock.Bytes)
	if err != nil {
		return err
	}
	interKeyBlock, _ := pem.Decode(interKeyPEM)
	interKey, err := x509.ParsePKCS1PrivateKey(interKeyBlock.Bytes)
	if err != nil {
		return err
	}
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{},
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, template, interCert, interKey)
	if err != nil {
		return err
	}
	path := filepath.Join(c.BaseDir, "crl.pem")
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}), 0644)
}
