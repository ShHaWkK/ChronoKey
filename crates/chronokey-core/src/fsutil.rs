use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use dirs::home_dir;

#[cfg(unix)]
use std::fs::Permissions;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub fn user_home_dir() -> io::Result<PathBuf> {
    home_dir().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home directory not found"))
}

pub fn chronokey_dir() -> io::Result<PathBuf> {
    let mut dir = user_home_dir()?;
    dir.push(".chronokey");
    Ok(dir)
}

pub fn ensure_dir(path: &Path) -> io::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

pub fn ensure_secure_file_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let perm = Permissions::from_mode(0o600);
        fs::set_permissions(path, perm)?;
    }

    #[cfg(windows)]
    {
        let mut permissions = path.metadata()?.permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions)?;
    }

    Ok(())
}

pub fn ssh_dir() -> io::Result<PathBuf> {
    let mut dir = user_home_dir()?;
    dir.push(".ssh");
    Ok(dir)
}
