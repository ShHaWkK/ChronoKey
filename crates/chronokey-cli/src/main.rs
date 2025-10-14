use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chronokey_core::abe::{AbeCiphertext, AbeEngine};
use chronokey_core::ca::CaStore;
use chronokey_core::fsutil::{ensure_dir, ssh_dir};
use chronokey_core::ssh;
use chronokey_core::token::{TokenClaims, TokenSigner};
use chronokey_core::validity::{normalize_validity, parse_ttl_seconds};
use clap::{Parser, Subcommand};
use rand::RngCore;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(name = "chronokey", about = "ChronoKey CLI for ephemeral SSH access")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialise a local CA keypair used for SSH certificate signing
    InitCa,
    /// Generate a new Ed25519 SSH keypair in the user's .ssh directory
    Keygen { label: String },
    /// Issue an SSH certificate using the local CA
    Issue {
        #[arg(long)]
        pubkey: PathBuf,
        #[arg(long)]
        user: String,
        #[arg(long)]
        valid: String,
        #[arg(long)]
        principals: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Bundle a certificate into a JSON structure, optionally encrypted locally
    Bundle {
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        principals: String,
        #[arg(long)]
        valid: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        encrypt_local: bool,
    },
    /// Issue a redeemable token signed by the HMAC secret
    TokenIssue {
        #[arg(long)]
        user: String,
        #[arg(long)]
        ttl: String,
        #[arg(long)]
        attrs: Option<String>,
        #[arg(long)]
        attrs_policy: Option<String>,
    },
    /// Redeem a token against a ChronoKey issuer service
    Redeem {
        #[arg(long)]
        token: String,
        #[arg(long)]
        pubkey: PathBuf,
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        abe_attrs: Option<String>,
    },
}

#[derive(Serialize)]
struct BundleDocument {
    identity: String,
    principals: Vec<String>,
    validity: String,
    cert_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    abe: Option<AbeCiphertext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_encrypted: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")

        .init();
    let cli = Cli::parse();
    match cli.command {
        Commands::InitCa => init_ca().await?,
        Commands::Keygen { label } => keygen(&label).await?,
        Commands::Issue {
            pubkey,
            user,
            valid,
            principals,
            out,
        } => issue(&pubkey, &user, &valid, principals, out).await?,
        Commands::Bundle {
            cert,
            identity,
            principals,
            valid,
            out,
            encrypt_local,
        } => bundle(cert, identity, principals, valid, out, encrypt_local).await?,
        Commands::TokenIssue {
            user,
            ttl,
            attrs,
            attrs_policy,
        } => token_issue(&user, &ttl, attrs, attrs_policy).await?,
        Commands::Redeem {
            token,
            pubkey,
            issuer,
            out,
            abe_attrs,
        } => redeem(&token, &pubkey, &issuer, out, abe_attrs).await?,
    }
    Ok(())
}

async fn init_ca() -> Result<()> {
    let store = CaStore::default()?;
    let keypair = store.init_ca()?;
    println!("CA created: {}", keypair.private_key.display());
    Ok(())
}

async fn keygen(label: &str) -> Result<()> {
    let mut path = ssh_dir().context("unable to locate ssh directory")?;
    ensure_dir(&path).context("failed to create ssh directory")?;
    path.push(label);
    let pubkey = ssh::generate_keypair(&path, &format!("ChronoKey client {label}"))?;
    println!("Keypair generated: {}", path.display());
    println!("Public key: {}", pubkey.display());
    Ok(())
}

async fn issue(
    pubkey: &Path,
    user: &str,
    valid: &str,
    principals: Option<String>,
    out: Option<PathBuf>,
) -> Result<()> {
    let validity = normalize_validity(valid)?;
    let store = CaStore::default()?;
    let principal_list = principals
        .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(|| vec![user.to_string()]);
    let cert_path =
        store.sign_public_key(pubkey, user, &principal_list, &validity, out.as_deref())?;
    println!("Certificate written to {}", cert_path.display());
    Ok(())
}

async fn bundle(
    cert: PathBuf,
    identity: String,
    principals: String,
    valid: String,
    out: PathBuf,
    encrypt_local: bool,
) -> Result<()> {
    let cert_bytes = fs::read(&cert)
        .with_context(|| format!("unable to read certificate {}", cert.display()))?;
    let doc = BundleDocument {
        identity,
        principals: principals
            .split(',')
            .map(|s| s.trim().to_string())
            .collect(),
        validity: valid,
        cert_b64: STANDARD.encode(&cert_bytes),
        abe: None,
        local_encrypted: if encrypt_local {
            Some(local_encrypt(&cert_bytes)?)
        } else {
            None
        },
    };
    let json = serde_json::to_string_pretty(&doc)?;
    fs::write(&out, json).with_context(|| format!("failed to write {}", out.display()))?;
    println!("Bundle saved to {}", out.display());
    Ok(())
}

fn local_encrypt(data: &[u8]) -> Result<String> {
    use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};
    use sha2::{Digest, Sha256};

    let passphrase = std::env::var("CHRONOKEY_BUNDLE_KEY")
        .context("CHRONOKEY_BUNDLE_KEY environment variable required for local encryption")?;
    let mut hasher = Sha256::new_with_prefix(passphrase.as_bytes());
    hasher.update(passphrase.as_bytes());
    let key_bytes = hasher.finalize();
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).expect("32 bytes");
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .context("AES-GCM encryption failure")?;
    let payload = serde_json::json!({
        "nonce": STANDARD.encode(nonce_bytes),
        "ciphertext": STANDARD.encode(ciphertext),
    });
    Ok(payload.to_string())
}

async fn token_issue(
    user: &str,
    ttl: &str,
    attrs: Option<String>,
    attrs_policy: Option<String>,
) -> Result<()> {
    let ttl_secs = parse_ttl_seconds(ttl)?;
    let attributes = parse_attrs_map(attrs.as_deref())?;
    let signer = TokenSigner::from_env("CHRONOKEY_HMAC_SECRET")?;
    let claims = TokenClaims::new(user.to_string(), ttl_secs, attributes.clone())?;
    let token = signer.sign(&claims)?;

    if let Some(policy) = attrs_policy {
        let ciphertext = AbeEngine::encrypt_for_policy(&policy, token.as_bytes())?;
        let package = serde_json::json!({
            "token": token,
            "policy": policy,
            "abe": ciphertext,
            "attrs": attributes,
        });
        println!("{}", serde_json::to_string_pretty(&package)?);
    } else {
        println!("{}", token);
    }

    Ok(())
}

async fn redeem(
    token_input: &str,
    pubkey: &Path,
    issuer: &str,
    out: Option<PathBuf>,
    abe_attrs: Option<String>,
) -> Result<()> {
    let token_material = load_token_input(token_input)?;
    let maybe_package: Result<TokenPackage, _> = serde_json::from_str(&token_material);
    let (mut token_str, abe_cipher) = if let Ok(package) = maybe_package {
        (package.token, package.abe)
    } else {
        (token_material, None)
    };

    if let Some(cipher) = abe_cipher {
        let attrs_str = abe_attrs.context("ABE attributes required to decrypt grant")?;
        let attr_list = parse_attr_list(&attrs_str);
        let user_keys = AbeEngine::generate_user_attr_keys(&attr_list);
        let decrypted = AbeEngine::decrypt_with_attrs(&cipher, &user_keys)?;
        token_str =
            String::from_utf8(decrypted).context("ABE decrypted token is not valid UTF-8")?;
    }

    let pubkey_contents = fs::read_to_string(pubkey)
        .with_context(|| format!("unable to read public key {}", pubkey.display()))?;
    let request = RedeemRequest {
        token: token_str,
        pubkey_b64: STANDARD.encode(pubkey_contents.as_bytes()),
    };

    let client = reqwest::Client::new();
    let response = client
        .post(issuer)
        .json(&request)
        .send()
        .await
        .context("failed to reach ChronoKey issuer")?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("issuer rejected redeem request: {}", body));
    }

    let reply: RedeemResponse = response.json().await.context("invalid issuer response")?;
    let cert_bytes = STANDARD
        .decode(reply.cert_b64)
        .context("issuer certificate payload invalid base64")?;
    let output = out.unwrap_or_else(|| derive_cert_path(pubkey));
    fs::write(&output, cert_bytes)
        .with_context(|| format!("failed to write certificate {}", output.display()))?;
    println!("Certificate written to {}", output.display());
    Ok(())
}

fn load_token_input(input: &str) -> Result<String> {
    let path = PathBuf::from(input);
    if path.exists() {
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("unable to read token file {}", path.display()))?;
        Ok(contents.trim().to_string())
    } else {
        Ok(input.to_string())
    }
}

fn parse_attrs_map(input: Option<&str>) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    if let Some(raw) = input {
        for entry in raw.split(',') {
            if entry.trim().is_empty() {
                continue;
            }
            let mut parts = entry.splitn(2, '=');
            let key = parts
                .next()
                .map(|s| s.trim().to_string())
                .ok_or_else(|| anyhow::anyhow!("invalid attribute entry"))?;
            let value = parts
                .next()
                .map(|s| s.trim().to_string())
                .ok_or_else(|| anyhow::anyhow!("attribute {key} missing value"))?;
            map.insert(key, value);
        }
    }
    Ok(map)
}

fn parse_attr_list(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn derive_cert_path(pubkey: &Path) -> PathBuf {
    let mut path = pubkey.to_path_buf();
    let file_name = pubkey
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("id_ed25519.pub");
    if file_name.ends_with(".pub") {
        path.set_file_name(format!("{}-cert.pub", &file_name[..file_name.len() - 4]));
    } else {
        path.set_file_name(format!("{}-cert.pub", file_name));
    }
    path
}

#[derive(serde::Deserialize)]
struct TokenPackage {
    token: String,
    #[serde(default)]
    abe: Option<AbeCiphertext>,
}

#[derive(serde::Serialize)]
struct RedeemRequest {
    token: String,
    pubkey_b64: String,
}

#[derive(serde::Deserialize)]
struct RedeemResponse {
    cert_b64: String,
}
