#!/usr/bin/env bash
set -euo pipefail

if ! command -v tempogate >/dev/null; then
  echo "tempogate binary not found in PATH" >&2
  exit 1
fi

if ! command -v tempogate-issuer >/dev/null; then
  echo "tempogate-issuer binary not found in PATH" >&2
  exit 1
fi

: "${TEMPOGATE_HMAC_SECRET:?Set TEMPOGATE_HMAC_SECRET before running}"

WORKDIR=${WORKDIR:-"$(mktemp -d)"}
SSH_LABEL=${SSH_LABEL:-"tempogate-demo"}
ISSUER_CONFIG="$WORKDIR/issuer.toml"
TOKEN_FILE="$WORKDIR/token.txt"
CERT_FILE="$WORKDIR/${SSH_LABEL}-cert.pub"

cat >"$ISSUER_CONFIG" <<TOML
ca_private_key = "${HOME}/.tempogate/ca_ed25519"
default_validity = "+30m"
bind_addr = "127.0.0.1:8080"
TOML

echo "[+] Initialising CA"
tempogate init-ca || true

echo "[+] Generating SSH keypair"
tempogate keygen "$SSH_LABEL"

echo "[+] Issuing token"
tempogate token issue --user "$USER" --ttl 30m --attrs "principals=$USER" >"$TOKEN_FILE"

issuer_log="$WORKDIR/issuer.log"

echo "[+] Starting issuer"
TEMPOGATE_HMAC_SECRET="$TEMPOGATE_HMAC_SECRET" tempogate-issuer --config "$ISSUER_CONFIG" \
  >"$issuer_log" 2>&1 &
ISSUER_PID=$!
trap 'kill $ISSUER_PID 2>/dev/null || true' EXIT
sleep 1

echo "[+] Redeeming token"
tempogate redeem --token "$(cat "$TOKEN_FILE")" --pubkey "$HOME/.ssh/${SSH_LABEL}.pub" \
  --issuer http://127.0.0.1:8080/redeem --out "$CERT_FILE"

echo "Certificate written to $CERT_FILE"
