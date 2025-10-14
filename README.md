# TempoGate

TempoGate is a cross-platform (Windows and Linux) toolchain for issuing time-bound SSH access grants. It provides:

* A CLI (`tempogate`) for local certificate authority (CA) operations and client workflows.
* A lightweight HTTP micro-service (`tempogate-issuer`) that redeems HMAC-signed tokens for short-lived SSH certificates.
* Prototype integrations for Attribute-Based Encryption (ABE) and zero-knowledge (ZK) proofs inspired by the UK NCSC [Advanced Cryptography](https://www.ncsc.gov.uk/whitepaper/advanced-cryptography) guidance.

> **Status**: security-sensitive code paths rely on mature Rust cryptography crates. The ABE and ZK modules are functional prototypes intended for experimentation only.

## Install

1. Install the Rust toolchain (`rustup`) and ensure the target hosts have the OpenSSH client (`ssh`, `ssh-keygen`).
2. Clone this repository and build the binaries:

```bash
cargo build --release
```

This produces `target/release/tempogate` and `target/release/tempogate-issuer` for the host platform.

## Quickstart

### Initialise the local CA

```bash
tempogate init-ca
```

Creates `~/.tempogate/ca_ed25519` and `ca_ed25519.pub` with restrictive permissions (or the equivalent under `%USERPROFILE%` on Windows).

### Generate a client keypair

```bash
tempogate keygen developer
```

Writes an Ed25519 keypair to `~/.ssh/developer` and `~/.ssh/developer.pub`.

### Issue a certificate directly from the CA

```bash
tempogate issue --pubkey ~/.ssh/developer.pub --user dev1 --valid +4h --principals dev1,ops
```

A certificate `developer-cert.pub` is emitted next to the public key.

### Issue and redeem a token

1. Export an HMAC secret for the issuer and CLI:

```bash
export TEMPOGATE_HMAC_SECRET="change-me-super-secret"
```

2. Issue a token that expires after 30 minutes and carries attributes:

```bash
tempogate token issue --user dev1 --ttl 30m --attrs environment=staging,principals=dev1
```

3. Start the issuer with a config (`issuer.toml`):

```toml
ca_private_key = "/home/you/.tempogate/ca_ed25519"
default_validity = "+1h"
bind_addr = "0.0.0.0:8080"
allowed_principals = ["dev1", "ops"]
```

```bash
TEMPOGATE_HMAC_SECRET="change-me-super-secret" tempogate-issuer --config issuer.toml
```

4. Redeem the token for a certificate:

```bash
tempogate redeem --token "<token-from-step-2>" --pubkey ~/.ssh/developer.pub --issuer http://localhost:8080/redeem --out ~/.ssh/developer-cert.pub
```

The issuer signs the supplied public key and returns a base64-encoded OpenSSH certificate.

### SSH server configuration

1. Copy the CA public key to the target server, e.g. `/etc/ssh/tempgate_ca.pub`.
2. In `sshd_config` set:

```
TrustedUserCAKeys /etc/ssh/tempgate_ca.pub
```

3. Reload the SSH daemon. Users can now authenticate using their private key plus the TempoGate-issued certificate.

## Bundling grants

`tempogate bundle` packages a certificate (and optional locally encrypted blob) into JSON for distribution:

```bash
export TEMPOGATE_BUNDLE_KEY="local-wrap-passphrase"
tempogate bundle --cert ~/.ssh/developer-cert.pub --identity dev1 --principals dev1,ops --valid +4h --out grant.json --encrypt-local
```

The resulting JSON contains the certificate base64 as well as an AES-GCM encrypted payload derived from the local passphrase.

## Redeem micro-service

`tempogate-issuer` exposes two endpoints:

* `POST /redeem` – body `{ "token": "…", "pubkey_b64": "…" }`
* `POST /redeem_zk` – same as `/redeem` plus fields for a Schnorr-style `zk_proof`

Responses return `{ "cert_b64": "…" }`. Audit logs are emitted in JSONL format with a forward-secure chain hash placeholder.

## Security posture & limits

* CA private keys remain local; `ssh-keygen` is invoked to avoid re-implementing OpenSSH formats.
* Tokens are HMAC-SHA256 signed and contain `sub`, `iat`, `exp`, `nonce`, and optional attribute key-value pairs.
* Token TTLs constrain the certificate lifetime on the issuer. Expired tokens are refused.
* Principals can be whitelisted by configuration. The CLI never transmits end-user private keys.
* Audit logs (JSON lines) include hashed linkage for post-hoc tamper detection. Cryptographic sealing should be added before production use.
* The ABE and ZKP modules are **experimental** – do not rely on them for production security without independent review.

## Advanced Cryptography prototypes

The `tempogate-core` crate provides the following experimental modules inspired by NCSC guidance:

* `abe`: exposes an interface for attribute-based encryption. The current mock uses AES-GCM with attribute-derived masks to wrap a content encryption key. Replace this module with a vetted Rust ABE implementation when one becomes available.
* `zkp`: offers a Schnorr-style proof-of-knowledge API over Ristretto255. It allows the issuer to require a non-interactive proof on `/redeem_zk`. Keys and proofs are serialised with base64 helpers.

Refer to the [NCSC Advanced Cryptography whitepaper](https://www.ncsc.gov.uk/whitepaper/advanced-cryptography) for architectural guidance, deployment considerations, and risk analysis.

## Tests

Run unit tests across the workspace:

```bash
cargo test
```

This covers token signing/verification, TTL parsing, ABE mock round-trips, and ZK proof verification.

## CI

GitHub Actions workflows build the binaries on Linux and Windows and run the Rust test suite. Artefacts are uploaded for each target to streamline distribution.

## Demo scripts

* `examples/demo.sh` – demonstrates the Unix workflow (CA init, keygen, token issue, redeem, SSH).
* `examples/demo.ps1` – PowerShell variant for Windows hosts.

Both scripts assume the issuer is reachable on `localhost:8080` and require environment variables for secrets.

## Roadmap

* Harden the audit log chaining with digital signatures.
* Swap the ABE mock for an interoperable ciphertext-policy ABE library when stable.
* Extend ZK proofs to bind to token attributes and reduce trust in the issuer during redeem.

TempoGate welcomes community contributions via issues or pull requests.
