#!/usr/bin/env bash
set -euo pipefail

if ! command -v chronokey >/dev/null; then
  echo "chronokey binary not found in PATH" >&2
  exit 1
fi

if ! command -v chronokey-issuer >/dev/null; then
  echo "chronokey-issuer binary not found in PATH" >&2
  exit 1
fi

: "${CHRONOKEY_HMAC_SECRET:?Set CHRONOKEY_HMAC_SECRET before running}"

WORKDIR=${WORKDIR:-"$(mktemp -d)"}
SSH_LABEL=${SSH_LABEL:-"chronokey-demo"}
ISSUER_CONFIG="$WORKDIR/issuer.toml"
TOKEN_FILE="$WORKDIR/token.txt"
CERT_FILE="$WORKDIR/${SSH_LABEL}-cert.pub"

cat >"$ISSUER_CONFIG" <<TOML
ca_private_key = "${HOME}/.chronokey/ca_ed25519"
default_validity = "+30m"
bind_addr = "127.0.0.1:8080"
TOML

echo "[+] Initialising CA"
chronokey init-ca || true

echo "[+] Generating SSH keypair"
chronokey keygen "$SSH_LABEL"

echo "[+] Issuing token"
chronokey token issue --user "$USER" --ttl 30m --attrs "principals=$USER" >"$TOKEN_FILE"

issuer_log="$WORKDIR/issuer.log"

echo "[+] Starting issuer"
CHRONOKEY_HMAC_SECRET="$CHRONOKEY_HMAC_SECRET" chronokey-issuer --config "$ISSUER_CONFIG" \
  >"$issuer_log" 2>&1 &
ISSUER_PID=$!
trap 'kill $ISSUER_PID 2>/dev/null || true' EXIT
sleep 1

echo "[+] Redeeming token"
chronokey redeem --token "$(cat "$TOKEN_FILE")" --pubkey "$HOME/.ssh/${SSH_LABEL}.pub" \
  --issuer http://127.0.0.1:8080/redeem --out "$CERT_FILE"

echo "Certificate written to $CERT_FILE"
