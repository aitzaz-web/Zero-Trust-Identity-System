# Zero-Trust Identity + mTLS System — Design Document

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          ZERO-TRUST IDENTITY SYSTEM                                   │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│   ┌─────────────┐     offline      ┌─────────────────┐     signs      ┌───────────┐ │
│   │   Root CA   │◄─────────────────│ Intermediate CA │◄───────────────│     RA    │ │
│   │  (offline)  │   signs once     │   (online)      │   issues       │ (API)     │ │
│   └─────────────┘                  └─────────────────┘   leaf certs   └─────┬─────┘ │
│          │                                  │                               │       │
│          │ trust bundle                     │ trust bundle                   │       │
│          ▼                                  ▼                               │       │
│   ┌──────────────────────────────────────────────────────────────────────────────┐  │
│   │                         TRUST BOUNDARY                                        │  │
│   │  ┌───────────┐    mTLS     ┌───────────┐    mTLS     ┌───────────┐           │  │
│   │  │ agent-a   │◄───────────►│ agent-b   │◄───────────►│ agent-c   │           │  │
│   │  │ service-a │             │ service-b │             │ service-c │           │  │
│   │  │  (C++)    │             │  (Java)   │             │ (optional)│           │  │
│   │  └───────────┘             └───────────┘             └───────────┘           │  │
│   └──────────────────────────────────────────────────────────────────────────────┘  │
│          │                     │                              │                     │
│          │ fetch certs         │ fetch certs                   │ fetch certs        │
│          ▼                     ▼                              ▼                     │
│   ┌─────────────────────────────────────────────────────────────────────────────┐  │
│   │  RA API (HTTPS, bootstrap token auth)  │  CRL Publisher (serves revocations) │  │
│   └─────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## 2. Components & Responsibilities

| Component | Responsibility | Tech |
|-----------|----------------|------|
| **Root CA** | Offline, signs Intermediate CA only. Trust anchor. | Go crypto/x509 |
| **Intermediate CA** | Online signer, issues leaf certs via RA. Stored securely. | Go crypto/x509 |
| **RA (Registration Authority)** | API for registration, issuance, revocation. Auth via bootstrap token. | Go, HTTP/gRPC |
| **CRL Publisher** | Serves Certificate Revocation List. Agents fetch periodically. | Go, HTTP |
| **ztca CLI** | Init, register, issue, revoke, status. Admin tool. | Go |
| **Agent** | Sidecar daemon: fetches certs, writes to disk, signals reload, rotates. | Go |
| **Service-A (C++)** | Demo service, mTLS client/server, OpenSSL, hot reload on SIGHUP. | C++, OpenSSL |
| **Service-B (Java)** | Demo service, mTLS client/server, JSSE, periodic cert refresh. | Java, JSSE |

## 3. Threat Model

### What We Defend Against

| Threat | Mitigation |
|--------|------------|
| **Rogue service without cert** | mTLS required; no cert → handshake fails |
| **Stolen certificate** | Short-lived certs (e.g., 24h), CRL, rotation before expiry |
| **MITM** | mTLS with mutual verification; no TLS termination in transit |
| **Mis-issued certs** | Audit trail (issuance logs), RA auth via bootstrap token |
| **Impersonation** | Identity from cert SAN (SPIFFE-like URI), not hostname |
| **Unauthorized caller** | Policy-based authz: caller identity → allowed endpoints |

### What We Explicitly Do NOT Cover (MVP)

- HSM/KMS for key storage
- Hardware attestation (TPM, Secure Enclave)
- OCSP stapling (CRL only in MVP)
- Perfect forward secrecy tuning beyond TLS defaults
- Full PKI product features (cross-signing, name constraints, etc.)

## 4. Trust Model

```
Root CA (self-signed, 10y)
  └── Intermediate CA (signed by Root, 1y)
        └── Leaf certs (signed by Intermediate, 24h default)
```

- **Trust bundle**: Root + Intermediate public certs. All services and agents load this.
- **Identity mapping**: SPIFFE-like URI in SAN, e.g. `spiffe://demo/ns/default/sa/service-a`
- **Verification**: Client and server verify chain to Intermediate (or Root), then extract identity from SAN URI. Hostname is NOT used for identity.

## 5. Certificate Lifecycle

```
┌──────────┐   ┌─────────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐
│ Register │──►│   Issue     │──►│ Distribute│──►│   Use     │──►│  Rotate   │
│ (ztca)   │   │ (RA + token)│   │ (agent)   │   │ (mTLS)    │   │ (agent)   │
└──────────┘   └─────────────┘   └───────────┘   └───────────┘   └───────────┘
       │                │                                                │
       │                │                                                │
       ▼                ▼                                                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Revocation: CRL updated → agents fetch → services check on new connections  │
└─────────────────────────────────────────────────────────────────────────────┘
```

1. **Issuance**: Service registers → receives bootstrap token → agent uses token to request leaf cert from RA
2. **Distribution**: Agent fetches cert+key+chain from RA, writes to disk, signals service
3. **Usage**: Service loads certs, establishes mTLS, verifies peer SAN
4. **Rotation**: Agent renews at 2/3 lifetime; hot reload so existing connections keep old cert, new use new
5. **Revocation**: RA adds serial to CRL; CRL publisher serves it; agents pull; services check on handshake

## 6. Failure Modes & Recovery

| Failure | Detection | Recovery |
|---------|-----------|----------|
| RA down | Agent cannot fetch cert | Retry with backoff; use cached cert until expiry |
| Cert expired before rotation | Handshake fails | Agent must renew earlier (2/3 rule); alert on rotation failure |
| Revoked cert still in use | New connections fail; existing may complete | Acceptable; short-lived certs limit exposure |
| Intermediate key compromise | Revoke Intermediate, re-issue from Root | Documented runbook; re-init from Root |
| Bootstrap token leaked | Log + revoke; rotate service identity | Design: short-lived token, one-time use preferred |

## 7. Data Models

### ServiceIdentity
```json
{
  "id": "service-a",
  "spiffe_id": "spiffe://demo/ns/default/sa/service-a",
  "created_at": "2025-02-15T00:00:00Z",
  "bootstrap_token_hash": "...",
  "active": true
}
```

### BootstrapToken
```json
{
  "service_id": "service-a",
  "token": "zt-bootstrap-xxxx",  // one-time or short-lived
  "expires_at": "2025-02-15T01:00:00Z",
  "used": false
}
```

### IssuedCert
```json
{
  "serial": "01:ab:cd:ef",
  "service_id": "service-a",
  "cert_pem": "-----BEGIN CERTIFICATE-----...",
  "key_pem": "-----BEGIN PRIVATE KEY-----...",
  "chain_pem": "-----BEGIN CERTIFICATE-----...",
  "expires_at": "2025-02-16T00:00:00Z",
  "issued_at": "2025-02-15T00:00:00Z"
}
```

### RevocationEntry
```json
{
  "serial": "01:ab:cd:ef",
  "revoked_at": "2025-02-15T12:00:00Z",
  "reason": "key_compromise"
}
```

### PolicyRule
```json
{
  "caller_id": "spiffe://demo/ns/default/sa/service-a",
  "allowed_endpoints": [
    "spiffe://demo/ns/default/sa/service-b:/api/*",
    "spiffe://demo/ns/default/sa/service-c:/health"
  ]
}
```

## 8. RA API Design

**Choice: REST over HTTPS** (simpler for agents, JSON, curl-friendly). gRPC would offer streaming and stronger typing but adds complexity; REST is sufficient for cert fetch (~few calls per hour per service).

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /v1/register | admin | Register service, return bootstrap token |
| POST | /v1/issue | Bootstrap token | Issue leaf cert for service |
| POST | /v1/revoke | admin | Revoke cert by serial or service |
| GET | /v1/status | admin | List certs, expirations, revoked |
| GET | /v1/crl | none | Get CRL (or served by crl-publisher) |

### Agent ↔ RA Auth

- Bootstrap token in `Authorization: Bearer <token>` or `X-Bootstrap-Token`
- RA validates token, maps to service_id, issues cert
- Token single-use or short TTL (e.g., 5 min) for initial bootstrap
