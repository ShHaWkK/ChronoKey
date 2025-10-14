use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use crate::fsutil::ensure_secure_file_permissions;

pub fn generate_key_pair(key_path: &Path, comment: &str) -> Result<()> {
    let ssh_keygen_path = find_ssh_keygen_path()?;
    let status = Command::new(ssh_keygen_path)
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

    ensure_secure_file_permissions(key_path)
        .context("failed to secure private key permissions")?;

    Ok(())
}

fn find_ssh_keygen_path() -> Result<PathBuf> {
    let common_paths = [
        "C:\Program Files\Git\usr\bin\ssh-keygen.exe",
        "C:\Windows\System32\OpenSSH\ssh-keygen.exe",
    ];

    for path in common_paths.iter() {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    // Fallback to just "ssh-keygen" if not found in common paths
    Ok(PathBuf::from("ssh-keygen"))
}
