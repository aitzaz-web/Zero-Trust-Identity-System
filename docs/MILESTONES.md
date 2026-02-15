# Implementation Milestones

## Milestone 1: MVP — End-to-End mTLS (Target: ~2–3 days)

**Goal**: Full mTLS between two services with issued certs.

### Tasks

1. **CA + ztca CLI**
   - [ ] `ztca init`: Create Root CA, Intermediate CA, trust bundle
   - [ ] `ztca register <service>`: Create service identity + bootstrap token
   - [ ] `ztca issue <service>`: Issue leaf cert (admin path for demo)
   - [ ] Store CA keys in `ca/` with strict permissions (600)

2. **RA API**
   - [ ] HTTP server with `/v1/register`, `/v1/issue` (bootstrap token auth), `/v1/status`
   - [ ] In-memory store for identities, tokens, issued certs
   - [ ] Issue certs with SAN URI = SPIFFE ID

3. **CRL Publisher**
   - [ ] Minimal HTTP server serving CRL at `/crl`
   - [ ] RA writes CRL on revoke; publisher reads from file or shared store

4. **Agent**
   - [ ] Fetch cert + key + chain from RA using bootstrap token
   - [ ] Write to `certs/` in container
   - [ ] Signal service (SIGHUP for C++, file touch for Java)

5. **Service-A (C++)**
   - [ ] OpenSSL mTLS server on port 8080
   - [ ] Load cert from file, verify client cert
   - [ ] SIGHUP handler to reload SSL_CTX

6. **Service-B (Java)**
   - [ ] JSSE mTLS server on port 8081
   - [ ] Load keystore/truststore from files
   - [ ] Optional: file watcher or periodic refresh

7. **Docker Compose**
   - [ ] ra, crl-publisher, agent-a + service-a, agent-b + service-b
   - [ ] Network isolation, init order

8. **Demo script**
   - [ ] `./demo.sh mvp`: Bring up, curl service-a → service-b over mTLS

**Exit criteria**: `curl -k` from service-a container to service-b over mTLS succeeds.

---

## Milestone 2: Rotation — Hot Reload, No Downtime (Target: ~1–2 days)

### Tasks

1. **Agent**
   - [ ] Renew at 2/3 cert lifetime
   - [ ] Fetch new cert, write atomically (temp + rename)
   - [ ] Signal reload after write

2. **C++ Service**
   - [ ] SIGHUP reloads SSL_CTX from disk
   - [ ] New connections use new cert; existing connections complete

3. **Java Service**
   - [ ] Periodic refresh (e.g., every 10 min) or inotify on cert dir
   - [ ] Reload SSLContext/KeyManager without restart

4. **Observability**
   - [ ] Log rotation events
   - [ ] Basic metric: `cert_age_seconds`, `rotation_success_total`

**Exit criteria**: Rotate cert manually or wait for auto-rotate; traffic continues without drop.

---

## Milestone 3: Revocation — CRL (Target: ~1 day)

### Tasks

1. **ztca revoke**
   - [ ] `ztca revoke <serial>` and `ztca revoke --service <name>`
   - [ ] RA updates CRL, publisher serves it

2. **Agent**
   - [ ] Fetch CRL periodically (e.g., every 60s)
   - [ ] Write CRL to `certs/crl.pem` or equivalent

3. **Services**
   - [ ] C++: Configure SSL_CTX to check CRL (X509_STORE_add_crl)
   - [ ] Java: RevocationChecker with CRL

4. **Demo**
   - [ ] Revoke service-a cert → new connection from service-a to service-b fails
   - [ ] Document OCSP as future work

**Exit criteria**: Revoked cert fails new handshakes; valid cert still works.

---

## Milestone 4: Observability (Target: ~1 day)

### Tasks

1. **Structured logs**
   - [ ] Issuance: who, when, serial, expiry
   - [ ] Rotation: service, old serial, new serial
   - [ ] Rejected handshakes: reason, peer identity
   - [ ] Revocation events

2. **Metrics** (Prometheus-style)
   - [ ] `mtls_handshakes_total{result="success|failure"}`
   - [ ] `mtls_cert_expiry_seconds`
   - [ ] `mtls_rotation_total{result="success|failure"}`

3. **Audit**
   - [ ] Persist issuance/revocation to audit log file
   - [ ] Optional: export to stdout for log aggregation

**Exit criteria**: Logs and metrics visible in demo; doc for tracing (design only).

---

## Milestone 5: Hardening (Target: ~1 day)

### Tasks

1. **Policy**
   - [ ] Policy file: caller identity → allowed callee endpoints
   - [ ] Service-B checks caller SAN against policy before processing
   - [ ] Demo: deny unauthorized identity even with valid cert

2. **Rate limits**
   - [ ] RA: limit issue requests per service (e.g., 10/min)
   - [ ] Protection against token brute-force

3. **Tamper resistance**
   - [ ] Document: CA key file permissions (600), read-only trust bundle
   - [ ] Optional: integrity check on trust bundle (checksum)

4. **Documentation**
   - [ ] HSM/KMS integration notes
   - [ ] Kubernetes deployment notes (ConfigMap for trust, Secret for tokens)

**Exit criteria**: Unauthorized identity denied; rate limit enforced; docs updated.
