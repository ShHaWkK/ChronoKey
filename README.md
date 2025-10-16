# ChronoKey

ChronoKey is a cross-platform (Windows and Linux) toolchain for granting short-lived SSH access without ever distributing private keys. It delivers a maintainable, layered architecture made of:

* A CLI (`chronokey`) that manages local certificate authority (CA) assets, issues SSH certificates, mints redeemable grants, and performs bundle/redeem workflows.
* A lightweight HTTP issuer service (`chronokey-issuer`) that validates HMAC tokens, signs SSH certificates on demand, and emits structured audit logs.
* A shared core crate (`chronokey-core`) containing cryptographic helpers, grant/token logic, mock Attribute-Based Encryption (ABE), and prototype zero-knowledge proof (ZKP) primitives inspired by the UK NCSC [Advanced Cryptography](https://www.ncsc.gov.uk/whitepaper/advanced-cryptography) guidance.

> **Security note**: Cryptographic building blocks rely on vetted Rust libraries. The ABE and ZKP modules are experimental facades that illustrate integration points and **must not** be treated as production hardened components.


Each crate is self-contained, documented, and covered by unit tests to keep the codebase approachable and maintainable.

## Install

1. Install the Rust toolchain via [`rustup`](https://rustup.rs/) and ensure the OpenSSH client (`ssh`, `ssh-keygen`) is available on the target machines.
2. Clone this repository and build the release binaries:

```bash
cargo build
```

```bash
cargo run 
```

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
