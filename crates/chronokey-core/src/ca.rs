use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use crate::fsutil::{chronokey_dir, ensure_dir, ensure_secure_file_permissions};

const CA_KEY_FILENAME: &str = "ca_ed25519";

#[derive(Debug, Clone)]
pub struct CaKeyPair {
    pub private_key: PathBuf,
    pub public_key: PathBuf,
}

impl CaKeyPair {
    pub fn new(private_key: PathBuf) -> Self {
        let mut public_key = private_key.clone();
        public_key.set_extension("pub");
        Self {
            private_key,
            public_key,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaStore {
    pub root: PathBuf,
}

impl CaStore {
    pub fn default() -> Result<Self> {
        let root = chronokey_dir().context("failed to resolve ChronoKey directory")?;
        ensure_dir(&root).context("failed to create ChronoKey directory")?;
        Ok(Self { root })
    }

    pub fn key_pair(&self) -> CaKeyPair {
        let mut path = self.root.clone();
        path.push(CA_KEY_FILENAME);
        CaKeyPair::new(path)
    }

    pub fn init_ca(&self) -> Result<CaKeyPair> {
        let key = self.key_pair();
        if key.private_key.exists() {
            return Err(anyhow::anyhow!(
                "CA already exists at {}",
                key.private_key.display()
            ));
        }

        let status = Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-f")
            .arg(&key.private_key)
            .arg("-N")
            .arg("")
            .arg("-C")
            .arg("ChronoKey CA")
            .status()
            .context("failed to execute ssh-keygen")?;

        if !status.success() {
            return Err(anyhow::anyhow!(
                "ssh-keygen failed with status {:?}",
                status.code()
            ));
        }

        ensure_secure_file_permissions(&key.private_key)
            .context("failed to secure CA private key permissions")?;

        Ok(key)
    }

    pub fn ensure_exists(&self) -> Result<CaKeyPair> {
        let key = self.key_pair();
        if !key.private_key.exists() {
            return Err(anyhow::anyhow!(
                "CA private key missing at {}. Run `chronokey init-ca`.",
                key.private_key.display()
            ));
        }
        Ok(key)
    }

    pub fn sign_public_key(
        &self,
        pubkey: &Path,
        identity: &str,
        principals: &[String],
        validity: &str,
        cert_out: Option<&Path>,
    ) -> Result<PathBuf> {
        let ca = self.ensure_exists()?;
        sign_with_ca(&ca, pubkey, identity, principals, validity, cert_out)
    }
}

pub fn sign_with_ca(
    ca: &CaKeyPair,
    pubkey: &Path,
    identity: &str,
    principals: &[String],
    validity: &str,
    cert_out: Option<&Path>,
) -> Result<PathBuf> {
    if !pubkey.exists() {
        return Err(anyhow::anyhow!(
            "public key {} does not exist",
            pubkey.display()
        ));
    }

    let principal_arg = if principals.is_empty() {
        identity.to_string()
    } else {
        principals.join(",")
    };

    let status = Command::new("ssh-keygen")
        .arg("-s")
        .arg(&ca.private_key)
        .arg("-I")
        .arg(identity)
        .arg("-n")
        .arg(&principal_arg)
        .arg("-V")
        .arg(validity)
        .arg(pubkey)
        .status()
        .context("failed to execute ssh-keygen for signing")?;

    if !status.success() {
        return Err(anyhow::anyhow!("ssh-keygen failed to sign key"));
    }

    let default_cert = default_cert_path(pubkey);
    let target_cert = cert_out
        .map(PathBuf::from)
        .unwrap_or_else(|| default_cert.clone());

    if let Some(output) = cert_out {
        if output != &default_cert {
            if output.exists() {
                fs::remove_file(output).with_context(|| {
                    format!("failed to remove existing file {}", output.display())
                })?;
            }
            fs::rename(&default_cert, output)
                .with_context(|| format!("failed to move certificate to {}", output.display()))?;
        }
    }

    Ok(target_cert)
}

fn default_cert_path(pubkey: &Path) -> PathBuf {
    let mut path = pubkey.to_path_buf();
    let filename = pubkey
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "id_ed25519.pub".to_string());
    if filename.ends_with(".pub") {
        path.set_file_name(format!("{}-cert.pub", &filename[..filename.len() - 4]));
    } else {
        path.set_file_name(format!("{}-cert.pub", filename));
    }
    path
}
