use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerConfig {
    pub ca_private_key: PathBuf,
    #[serde(default)]
    pub default_validity: Option<String>,
    #[serde(default)]
    pub allowed_principals: Option<Vec<String>>,
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_hmac_env")]
    pub hmac_secret_env: String,
}

fn default_bind_addr() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_hmac_env() -> String {
    "CHRONOKEY_HMAC_SECRET".to_string()
}

#[derive(Debug, Clone)]
pub struct ValidityPolicy {
    pub default_validity: String,
}

impl ValidityPolicy {
    pub fn from_config(config: &IssuerConfig) -> Self {
        Self {
            default_validity: config
                .default_validity
                .clone()
                .unwrap_or_else(|| "+4h".to_string()),
        }
    }
}

pub fn load_config(path: &Path) -> Result<IssuerConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("unable to read config {}", path.display()))?;
    if path
        .extension()
        .map(|ext| ext == "yaml" || ext == "yml")
        .unwrap_or(false)
    {
        serde_yaml::from_str(&raw).context("failed to parse YAML config")
    } else {
        toml::from_str(&raw).context("failed to parse TOML config")
    }
}
