use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

pub fn generate_keypair(path: &Path, comment: &str) -> Result<PathBuf> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let status = Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-f")
        .arg(path)
        .arg("-N")
        .arg("")
        .arg("-C")
        .arg(comment)
        .status()
        .context("failed to execute ssh-keygen")?;

    if !status.success() {
        return Err(anyhow::anyhow!(
            "ssh-keygen failed with status {:?}",
            status.code()
        ));
    }

    let mut pubkey = path.to_path_buf();
    pubkey.set_extension("pub");
    Ok(pubkey)
}
