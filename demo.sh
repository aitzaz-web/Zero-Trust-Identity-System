#!/bin/bash
# Zero-Trust mTLS Demo Script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
CADIR="${CADIR:-ca}"
ZTCA="${ZTCA:-./bin/ztca}"

ensure_ztca() {
    if [ ! -x "$ZTCA" ]; then
        make build
    fi
}

ensure_ca() {
    if [ ! -f "$CADIR/trust-bundle.pem" ]; then
        ensure_ztca
        $ZTCA init
    fi
}

register_services() {
    ensure_ztca
    ensure_ca
    # Register via RA API (requires RA running) or use ztca for local bootstrap
    echo "Registering services..."
    TOKEN_A=$(curl -s "http://localhost:8443/v1/register?service=service-a" | grep -o '"bootstrap_token":"[^"]*"' | cut -d'"' -f4)
    TOKEN_B=$(curl -s "http://localhost:8443/v1/register?service=service-b" | grep -o '"bootstrap_token":"[^"]*"' | cut -d'"' -f4)
    export BOOTSTRAP_TOKEN_A="$TOKEN_A"
    export BOOTSTRAP_TOKEN_B="$TOKEN_B"
    echo "BOOTSTRAP_TOKEN_A=$TOKEN_A"
    echo "BOOTSTRAP_TOKEN_B=$TOKEN_B"
}

case "${1:-help}" in
    mvp)
        ensure_ca
        echo "Starting services (RA must be up first for bootstrap tokens)..."
        echo "If first run: 1) docker compose up -d ra 2) sleep 5 3) ./demo.sh register 4) docker compose up -d"
        echo ""
        echo "Quick start: export BOOTSTRAP_TOKEN_A=\$(curl -s 'http://localhost:8443/v1/register?service=service-a'|jq -r .bootstrap_token)"
        echo "            export BOOTSTRAP_TOKEN_B=\$(curl -s 'http://localhost:8443/v1/register?service=service-b'|jq -r .bootstrap_token)"
        echo "            docker compose up -d"
        docker compose up -d
        echo ""
        echo "Wait ~15s for agents to fetch certs, then:"
        echo "  docker compose exec service-a curl -k --cert /certs/cert.pem --key /certs/key.pem --cacert /certs/chain.pem https://service-b:8081/"
        ;;
    init)
        ensure_ztca
        $ZTCA init
        echo "CA initialized. Run: docker compose up -d ra"
        echo "Then register: ./demo.sh register"
        ;;
    register)
        ensure_ca
        docker compose up -d ra
        sleep 5
        register_services
        echo ""
        echo "Export these and run: docker compose up -d"
        ;;
    test)
        echo "Testing mTLS from service-a to service-b..."
        docker compose exec service-a curl -kv --cert /certs/cert.pem --key /certs/key.pem --cacert /certs/chain.pem https://service-b:8081/ 2>/dev/null | tail -5
        ;;
    revoke)
        echo "Revoking service-a (demo)..."
        curl -s -X POST "http://localhost:8443/v1/revoke?service=service-a"
        echo "Revoked. New connections from service-a should fail."
        ;;
    down)
        docker compose down
        ;;
    *)
        echo "Usage: $0 {mvp|init|register|test|revoke|down}"
        echo "  mvp     - Bring up full stack"
        echo "  init    - Initialize CA"
        echo "  register - Register services, output bootstrap tokens"
        echo "  test    - Curl service-b from service-a over mTLS"
        echo "  revoke  - Revoke service-a cert"
        echo "  down    - Tear down"
        ;;
esac
