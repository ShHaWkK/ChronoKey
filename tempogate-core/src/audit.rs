use std::sync::Mutex;

use once_cell::sync::Lazy;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::info;

#[derive(Debug, Serialize)]
pub struct AuditLogEntry<'a> {
    pub timestamp: &'a str,
    pub token_id: &'a str,
    pub principals: &'a [String],
    pub validity: &'a str,
    pub client_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_hash: Option<String>,
}

static PREVIOUS_HASH: Lazy<Mutex<Option<Vec<u8>>>> = Lazy::new(|| Mutex::new(None));

pub fn emit(entry: AuditLogEntry<'_>) {
    let mut prev = PREVIOUS_HASH.lock().expect("audit log mutex poisoned");
    let mut hasher = Sha256::new();
    if let Some(ref previous_hash) = *prev {
        hasher.update(previous_hash);
    }
    let serialized = serde_json::to_vec(&entry).expect("audit entry serializable");
    hasher.update(&serialized);
    let digest = hasher.finalize().to_vec();
    let hex_hash = hex::encode(&digest);
    *prev = Some(digest);

    let log_line = serde_json::json!({
        "timestamp": entry.timestamp,
        "token_id": entry.token_id,
        "principals": entry.principals,
        "validity": entry.validity,
        "client_ip": entry.client_ip,
        "chain_hash": hex_hash,
    });
    info!(target: "audit", "{}", log_line);
}
