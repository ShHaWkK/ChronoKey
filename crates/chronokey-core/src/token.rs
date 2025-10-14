use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::NewMac;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;

pub type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub nonce: String,
    #[serde(default)]
    pub attrs: HashMap<String, String>,
}

impl TokenClaims {
    pub fn new(
        sub: impl Into<String>,
        ttl_secs: i64,
        attrs: HashMap<String, String>,
    ) -> Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before unix epoch")?;
        let iat = now.as_secs() as i64;
        Ok(Self {
            sub: sub.into(),
            iat,
            exp: iat + ttl_secs,
            nonce: random_nonce(),
            attrs,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TokenSigner {
    secret: Vec<u8>,
}

impl TokenSigner {
    pub fn new(secret: Vec<u8>) -> Self {
        Self { secret }
    }

    pub fn from_env(var: &str) -> Result<Self> {
        let secret =
            std::env::var(var).with_context(|| format!("missing HMAC secret env var {}", var))?;
        Ok(Self::new(secret.into_bytes()))
    }

    pub fn sign(&self, claims: &TokenClaims) -> Result<String> {
        let header = serde_json::json!({ "alg": "HS256", "typ": "CK" });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| anyhow!("invalid hmac key"))?;
        mac.update(signing_input.as_bytes());
        let signature = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
        Ok(format!("{}.{}", signing_input, sig_b64))
    }

    pub fn verify(&self, token: &str) -> Result<GrantToken> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow::anyhow!("invalid token format"));
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| anyhow!("invalid hmac key"))?;
        mac.update(signing_input.as_bytes());
        let expected = mac.finalize().into_bytes();
        let provided = URL_SAFE_NO_PAD
            .decode(parts[2])
            .context("invalid base64 signature")?;
        if &expected[..] != &provided[..] {
            return Err(anyhow::anyhow!("token signature mismatch"));
        }
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .context("invalid base64 payload")?;
        let claims: TokenClaims =
            serde_json::from_slice(&payload_bytes).context("invalid token payload")?;
        Ok(GrantToken {
            raw: token.to_string(),
            claims,
        })
    }
}

#[derive(Debug, Clone)]
pub struct GrantToken {
    pub raw: String,
    pub claims: TokenClaims,
}

impl GrantToken {
    pub fn is_expired(&self) -> Result<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before unix epoch")?;
        Ok(now.as_secs() as i64 >= self.claims.exp)
    }

    pub fn token_id(&self) -> String {
        let digest = Sha256::digest(self.raw.as_bytes());
        hex::encode(&digest[..16])
    }
}

fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_token() {
        let signer = TokenSigner::new(b"secret".to_vec());
        let claims = TokenClaims::new("alice", 60, HashMap::new()).unwrap();
        let token = signer.sign(&claims).unwrap();
        let verified = signer.verify(&token).unwrap();
        assert_eq!(verified.claims.sub, "alice");
        assert!(!verified.is_expired().unwrap());
    }
}
