package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultValidityRoot    = 10 * 365 * 24 * time.Hour
	DefaultValidityInter   = 365 * 24 * time.Hour
	DefaultValidityLeaf    = 24 * time.Hour
	KeySize                = 2048
	SerialCounterStart     = 1
)

// Config holds paths for CA artifacts.
type Config struct {
	BaseDir string
}

// Init creates Root CA and Intermediate CA, writes trust bundle.
func (c *Config) Init() error {
	if err := os.MkdirAll(c.BaseDir, 0700); err != nil {
		return err
	}
	rootKey, rootCert, err := createRootCA()
	if err != nil {
		return err
	}
	if err := c.writeKeyCert("root", rootKey, rootCert); err != nil {
		return err
	}
	interKey, interCert, err := createIntermediateCA(rootKey, rootCert)
	if err != nil {
		return err
	}
	if err := c.writeKeyCert("intermediate", interKey, interCert); err != nil {
		return err
	}
	return c.writeTrustBundle(rootCert, interCert)
}

func createRootCA() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Zero-Trust Demo"},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(DefaultValidityRoot),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func createIntermediateCA(parentKey *rsa.PrivateKey, parentCert *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Zero-Trust Demo"},
			CommonName:   "Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(DefaultValidityInter),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func (c *Config) writeKeyCert(name string, key *rsa.PrivateKey, cert *x509.Certificate) error {
	keyPath := filepath.Join(c.BaseDir, name+".key")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	certPath := filepath.Join(c.BaseDir, name+".crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return os.WriteFile(certPath, certPEM, 0644)
}

func (c *Config) writeTrustBundle(root, inter *x509.Certificate) error {
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Raw})...)
	path := filepath.Join(c.BaseDir, "trust-bundle.pem")
	return os.WriteFile(path, bundle, 0644)
}

// IssueLeaf creates a leaf cert for the given SPIFFE ID.
func (c *Config) IssueLeaf(spiffeID string, validity time.Duration) (certPEM, keyPEM, chainPEM string, serial string, err error) {
	interKeyPEM, err := os.ReadFile(filepath.Join(c.BaseDir, "intermediate.key"))
	if err != nil {
		return "", "", "", "", err
	}
	interCertPEM, err := os.ReadFile(filepath.Join(c.BaseDir, "intermediate.crt"))
	if err != nil {
		return "", "", "", "", err
	}
	key, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return "", "", "", "", err
	}
	keyBlock, _ := pem.Decode(interKeyPEM)
	interKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return "", "", "", "", err
	}
	interCertBlock, _ := pem.Decode(interCertPEM)
	interCert, err := x509.ParseCertificate(interCertBlock.Bytes)
	if err != nil {
		return "", "", "", "", err
	}
	if validity == 0 {
		validity = DefaultValidityLeaf
	}
	serialInt, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", "", err
	}
	serial = fmt.Sprintf("%X", serialInt)
	template := &x509.Certificate{
		SerialNumber: serialInt,
		Subject: pkix.Name{
			Organization: []string{"Zero-Trust Demo"},
			CommonName:   spiffeID,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(validity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{parseSpiffeURI(spiffeID)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, interCert, &key.PublicKey, interKey)
	if err != nil {
		return "", "", "", "", err
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	chainPEM = certPEM + string(interCertPEM)
	return certPEM, keyPEM, chainPEM, serial, nil
}

func parseSpiffeURI(id string) *url.URL {
	var uri string
	switch {
	case len(id) == 0:
		uri = "spiffe://demo/ns/default/sa/unknown"
	case len(id) >= 7 && id[:7] == "spiffe:":
		uri = id
	case id[0] == '/':
		uri = "spiffe://demo" + id
	default:
		uri = "spiffe://" + id
	}
	u, _ := url.Parse(uri)
	return u
}
