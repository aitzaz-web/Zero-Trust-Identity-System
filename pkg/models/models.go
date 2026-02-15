package models

import "time"

// ServiceIdentity represents a registered service.
type ServiceIdentity struct {
	ID               string    `json:"id"`
	SpiffeID         string    `json:"spiffe_id"`
	CreatedAt        time.Time `json:"created_at"`
	BootstrapTokenHash string  `json:"-"` // never expose
	Active           bool      `json:"active"`
}

// BootstrapToken is a one-time or short-lived token for cert issuance.
type BootstrapToken struct {
	ServiceID string    `json:"service_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

// IssuedCert holds PEM-encoded cert, key, chain, and metadata.
type IssuedCert struct {
	Serial    string    `json:"serial"`
	ServiceID string    `json:"service_id"`
	CertPEM   string    `json:"cert_pem"`
	KeyPEM    string    `json:"key_pem"`
	ChainPEM  string    `json:"chain_pem"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
}

// RevocationEntry records a revoked certificate.
type RevocationEntry struct {
	Serial   string    `json:"serial"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason   string    `json:"reason"`
}

// PolicyRule defines caller -> allowed callee endpoints.
type PolicyRule struct {
	CallerID         string   `json:"caller_id"`
	AllowedEndpoints []string `json:"allowed_endpoints"`
}
