# Zero-Trust Identity + mTLS System

A lightweight internal CA and certificate lifecycle system enabling mutual TLS (mTLS) between cloud microservices.

## Quick Start

```bash
# 1. Initialize CA (root + intermediate + trust bundle + CRL)
make init
# or: ./bin/ztca init

# 2. Build and start RA
make build
docker compose up -d ra
sleep 5

# 3. Register services, get bootstrap tokens
export BOOTSTRAP_TOKEN_A=$(curl -s "http://localhost:8443/v1/register?service=service-a" | jq -r .bootstrap_token)
export BOOTSTRAP_TOKEN_B=$(curl -s "http://localhost:8443/v1/register?service=service-b" | jq -r .bootstrap_token)

# 4. Bring up full stack
docker compose up -d
sleep 15

# 5. Demo: service-a calls service-b over mTLS
docker compose exec service-a curl -kv \
  --cert /certs/cert.pem --key /certs/key.pem --cacert /certs/chain.pem \
  https://service-b:8081/

# 6. Revoke and verify failure
curl -X POST "http://localhost:8443/v1/revoke?service=service-a"
# New connections from service-a will fail (CRL check)
```

See `docs/CLI_COMMANDS.md` for exact commands.

## Repo Structure

```
.
├── ca/                     # CA files (root, intermediate, trust bundle) — created by ztca init
├── docs/
│   ├── DESIGN.md           # Architecture, threat model, data models
│   └── MILESTONES.md       # Implementation plan
├── pkg/                    # Shared Go packages
│   ├── ca/                 # CA operations
│   ├── models/             # Data models
│   └── api/                # RA API client
├── cmd/
│   ├── ztca/               # CLI: init, register, issue, revoke, status
│   └── ra/                 # Registration Authority API server
├── internal/
│   ├── crl/                # CRL publisher
│   └── agent/              # Cert fetch + rotation agent
├── services/
│   ├── service-a/          # C++ mTLS service (OpenSSL)
│   └── service-b/          # Java mTLS service (JSSE)
├── docker-compose.yml
├── demo.sh
└── Makefile
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `ztca init` | Create Root + Intermediate CA, trust bundle |
| `ztca register <service>` | Create service identity, output bootstrap token |
| `ztca issue <service>` | Issue leaf cert (admin; agents use API) |
| `ztca revoke <serial>` | Revoke cert by serial |
| `ztca revoke --service <name>` | Revoke all certs for service |
| `ztca status` | List active certs, expirations, revoked |

## Security Notes

- CA private keys stored with 600 permissions; document HSM/KMS for production
- Bootstrap tokens: short-lived, single-use preferred
- Short-lived leaf certs (24h default), rotate at 2/3 lifetime

## License

MIT
