# ChronoKey

ChronoKey is a cross-platform (Windows and Linux) toolchain for granting short-lived SSH access without ever distributing private keys. It delivers a maintainable, layered architecture made of:

* A CLI (`chronokey`) that manages local certificate authority (CA) assets, issues SSH certificates, mints redeemable grants, and performs bundle/redeem workflows.
* A lightweight HTTP issuer service (`chronokey-issuer`) that validates HMAC tokens, signs SSH certificates on demand, and emits structured audit logs.
* A shared core crate (`chronokey-core`) containing cryptographic helpers, grant/token logic, mock Attribute-Based Encryption (ABE), and prototype zero-knowledge proof (ZKP) primitives inspired by the UK NCSC [Advanced Cryptography](https://www.ncsc.gov.uk/whitepaper/advanced-cryptography) guidance.

> **Security note**: Cryptographic building blocks rely on vetted Rust libraries. The ABE and ZKP modules are experimental facades that illustrate integration points and **must not** be treated as production hardened components.

## Repository layout

```
crates/
├── chronokey-core      # shared library for crypto, grants, config, and filesystem helpers
├── chronokey-cli       # end-user CLI (`chronokey`) built on the core crate
└── chronokey-issuer    # Axum-based HTTP microservice for token redemption
examples/
├── demo.sh             # bash walkthrough of the CLI + issuer roundtrip
└── demo.ps1            # PowerShell variant for Windows hosts
```

Each crate is self-contained, documented, and covered by unit tests to keep the codebase approachable and maintainable.

## Install

1. Install the Rust toolchain via [`rustup`](https://rustup.rs/) and ensure the OpenSSH client (`ssh`, `ssh-keygen`) is available on the target machines.
2. Clone this repository and build the release binaries:

```bash
cargo build --release
```

The build produces `target/release/chronokey` and `target/release/chronokey-issuer` for the host platform. Cross-compilation can be driven through Cargo's standard target selection (`--target <triple>`).

## Quickstart

### Initialise the local CA

```bash
chronokey init-ca
```

Creates `~/.chronokey/ca_ed25519` and `ca_ed25519.pub` with restrictive permissions (or the `%USERPROFILE%\.chronokey` equivalent on Windows).

### Generate a client keypair

```bash
chronokey keygen developer
```

Writes an Ed25519 keypair to `~/.ssh/developer` and `~/.ssh/developer.pub`.

### Issue a certificate directly from the CA

```bash
chronokey issue --pubkey ~/.ssh/developer.pub --user dev1 --valid +4h --principals dev1,ops
```

A certificate `developer-cert.pub` is emitted next to the public key.

### Issue and redeem a token

1. Export an HMAC secret for both the CLI and issuer:

```bash
export CHRONOKEY_HMAC_SECRET="change-me-super-secret"
```

2. Issue a token that expires after 30 minutes and carries attributes:

```bash
chronokey token issue --user dev1 --ttl 30m --attrs environment=staging,principals=dev1
```

3. Prepare an issuer configuration (`issuer.toml`):

```toml
ca_private_key = "/home/you/.chronokey/ca_ed25519"
default_validity = "+1h"
bind_addr = "0.0.0.0:8080"
allowed_principals = ["dev1", "ops"]
```

4. Launch the issuer:

```bash
CHRONOKEY_HMAC_SECRET="change-me-super-secret" chronokey-issuer --config issuer.toml
```

5. Redeem the token for a certificate:

```bash
chronokey redeem --token "<token-from-step-2>" --pubkey ~/.ssh/developer.pub --issuer http://localhost:8080/redeem --out ~/.ssh/developer-cert.pub
```

The issuer signs the supplied public key and returns a base64-encoded OpenSSH certificate.

### SSH server configuration

1. Copy the CA public key to the target server, e.g. `/etc/ssh/chronokey_ca.pub`.
2. In `sshd_config` set:

```
TrustedUserCAKeys /etc/ssh/chronokey_ca.pub
```

3. Reload the SSH daemon. Users can now authenticate using their private key plus the ChronoKey-issued certificate.

## Bundling grants

`chronokey bundle` packages a certificate (and optional locally encrypted blob) into JSON for distribution:

```bash
export CHRONOKEY_BUNDLE_KEY="local-wrap-passphrase"
chronokey bundle --cert ~/.ssh/developer-cert.pub --identity dev1 --principals dev1,ops --valid +4h --out grant.json --encrypt-local
```

The resulting JSON contains the certificate base64 as well as an AES-GCM encrypted payload derived from the local passphrase.

## Redeem microservice

`chronokey-issuer` exposes two endpoints:

* `POST /redeem` – body `{ "token": "…", "pubkey_b64": "…" }`
* `POST /redeem_zk` – same as `/redeem` plus a Schnorr-style `zk_proof`

Responses return `{ "cert_b64": "…" }`. Audit logs are emitted in JSON Lines with a forward-secure chain hash placeholder for future hardening.

## Security posture & limits

* CA private keys remain local; `ssh-keygen` is invoked to avoid re-implementing OpenSSH formats.
* Tokens are HMAC-SHA256 signed and contain `sub`, `iat`, `exp`, `nonce`, and optional attribute key-value pairs.
* Token TTLs constrain certificate lifetime on the issuer. Expired or malformed tokens are rejected.
* Principals can be whitelisted via configuration. The CLI never transmits end-user private keys.
* Audit logs (JSONL) include hashed linkage for post-hoc tamper detection. Digital signatures should be added before production usage.
* The ABE and ZKP modules are **experimental** – do not rely on them for production security without independent review.

## Advanced cryptography prototypes

The `chronokey-core` crate provides the following experimental modules aligned with the NCSC guidance:

* `abe`: exposes an interface for attribute-based encryption. The current mock uses AES-GCM with attribute-derived masks to wrap a content encryption key. Replace this module with a vetted Rust ABE implementation when available.
* `zkp`: offers a Schnorr-style proof-of-knowledge API over Ristretto255, enabling the issuer to require a non-interactive proof on `/redeem_zk`.

Refer to the [NCSC Advanced Cryptography whitepaper](https://www.ncsc.gov.uk/whitepaper/advanced-cryptography) for architectural guidance, deployment considerations, and risk analysis.

## Testing

Run unit tests across the workspace:

```bash
cargo test
```

This covers token signing/verification, TTL parsing, ABE mock round-trips, and ZK proof verification.

## Continuous integration

GitHub Actions workflows build the binaries on Linux and Windows and run the Rust test suite. Artefacts are uploaded for each target to streamline distribution.

## Demo scripts

* `examples/demo.sh` – demonstrates the Unix workflow (CA init, keygen, token issue, redeem, SSH).
* `examples/demo.ps1` – PowerShell variant for Windows hosts.

Both scripts assume the issuer is reachable on `localhost:8080` and require environment variables for secrets.

## Roadmap

* Harden the audit log chaining with digital signatures.
* Swap the ABE mock for an interoperable ciphertext-policy ABE library when stable.
* Extend ZK proofs to bind to token attributes and reduce trust in the issuer during redeem.

ChronoKey welcomes community contributions via issues or pull requests.
