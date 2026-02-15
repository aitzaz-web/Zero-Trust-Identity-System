# CLI Commands & Demo Workflow

## Prerequisites

- Docker & Docker Compose
- Go 1.21+ (for building ztca locally)
- Make (optional)

## Exact Commands to Run the Demo

### 1. Initialize CA

```bash
make init
# or: ./bin/ztca init
```

Creates `ca/` with root.key, root.crt, intermediate.key, intermediate.crt, trust-bundle.pem.

### 2. Build All Components

```bash
make build
```

Builds: `bin/ztca`, `bin/ra`, `bin/crl-publisher`, `bin/agent`, C++ service-a, Java service-b.

### 3. Create Empty CRL (for demo)

```bash
touch ca/crl.pem
# or create minimal CRL; RA will populate on revoke
```

### 4. Start RA First

```bash
docker compose up -d ra
sleep 5
```

### 5. Register Services & Get Bootstrap Tokens

```bash
TOKEN_A=$(curl -s "http://localhost:8443/v1/register?service=service-a" | jq -r .bootstrap_token)
TOKEN_B=$(curl -s "http://localhost:8443/v1/register?service=service-b" | jq -r .bootstrap_token)
export BOOTSTRAP_TOKEN_A="$TOKEN_A"
export BOOTSTRAP_TOKEN_B="$TOKEN_B"
echo "BOOTSTRAP_TOKEN_A=$TOKEN_A"
echo "BOOTSTRAP_TOKEN_B=$TOKEN_B"
```

### 6. Bring Up Full Stack

```bash
docker compose up -d
```

### 7. Wait for Agents to Fetch Certs

```bash
sleep 15
```

### 8. Test mTLS: service-a → service-b

```bash
docker compose exec service-a curl -kv \
  --cert /certs/cert.pem \
  --key /certs/key.pem \
  --cacert /certs/chain.pem \
  https://service-b:8081/
```

Expected: `OK from service-b`

### 9. Revoke service-a & Verify Failure

```bash
curl -X POST "http://localhost:8443/v1/revoke?service=service-a"
# New connections from service-a should fail (CRL check on next handshake)
```

### 10. Tear Down

```bash
docker compose down
```

## One-Liner Full Demo

```bash
make init build && \
docker compose up -d ra && sleep 5 && \
export BOOTSTRAP_TOKEN_A=$(curl -s "http://localhost:8443/v1/register?service=service-a" | jq -r .bootstrap_token) && \
export BOOTSTRAP_TOKEN_B=$(curl -s "http://localhost:8443/v1/register?service=service-b" | jq -r .bootstrap_token) && \
touch ca/crl.pem 2>/dev/null; docker compose up -d && \
echo "Wait 15s then: docker compose exec service-a curl -kv --cert /certs/cert.pem --key /certs/key.pem --cacert /certs/chain.pem https://service-b:8081/"
```
