use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct AbeUserKey {
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbeCiphertext {
    pub policy: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub wrapped_keys: Vec<WrappedKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    pub attr_hash: String,
    pub wrapped_key_b64: String,
}

pub struct AbeEngine;

impl AbeEngine {
    pub fn generate_user_attr_keys(attrs: &[String]) -> AbeUserKey {
        AbeUserKey {
            attributes: attrs.to_vec(),
        }
    }

    pub fn encrypt_for_policy(policy: &str, plaintext: &[u8]) -> Result<AbeCiphertext> {
        let key = random_bytes::<32>();
        let nonce_bytes = random_bytes::<12>();
        let cipher = Aes256Gcm::new_from_slice(&key).expect("key length");
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .context("AES-GCM encryption failure")?;

        let mut wrapped_keys = Vec::new();
        for attr in policy_attributes(policy) {
            let attr_hash = hash_str(&attr);
            let mask = derive_mask(&attr, policy);
            let wrapped_key: Vec<u8> = key.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect();
            wrapped_keys.push(WrappedKey {
                attr_hash,
                wrapped_key_b64: STANDARD.encode(wrapped_key),
            });
        }

        Ok(AbeCiphertext {
            policy: policy.to_string(),
            nonce_b64: STANDARD.encode(nonce_bytes),
            ciphertext_b64: STANDARD.encode(ciphertext),
            wrapped_keys,
        })
    }

    pub fn decrypt_with_attrs(
        ciphertext: &AbeCiphertext,
        user_keys: &AbeUserKey,
    ) -> Result<Vec<u8>> {
        for attr in &user_keys.attributes {
            let attr_hash = hash_str(attr);
            if let Some(wrapped) = ciphertext
                .wrapped_keys
                .iter()
                .find(|wk| wk.attr_hash == attr_hash)
            {
                let mask = derive_mask(attr, &ciphertext.policy);
                let wrapped_key = STANDARD
                    .decode(&wrapped.wrapped_key_b64)
                    .context("invalid wrapped key encoding")?;
                let key: Vec<u8> = wrapped_key
                    .iter()
                    .zip(mask.iter())
                    .map(|(a, b)| a ^ b)
                    .collect();
                let cipher = Aes256Gcm::new_from_slice(&key)
                    .map_err(|_| anyhow!("invalid AES key length"))?;
                let nonce_bytes = STANDARD
                    .decode(&ciphertext.nonce_b64)
                    .context("invalid nonce encoding")?;
                let nonce_array: &[u8; 12] = nonce_bytes.as_slice().try_into().context("invalid nonce length")?;
                let nonce = Nonce::from(*nonce_array);
                let cipher_bytes = STANDARD
                    .decode(&ciphertext.ciphertext_b64)
                    .context("invalid ciphertext encoding")?;
                return cipher
                    .decrypt(&nonce, cipher_bytes.as_ref())
                    .context("AES-GCM decryption failure");
            }
        }

        Err(anyhow!(
            "attributes did not satisfy policy; this prototype mock does not support complex policies"
        ))
    }
}

fn policy_attributes(policy: &str) -> Vec<String> {
    policy
        .split(|c| c == '|' || c == ',' || c == ';')
        .flat_map(|segment| segment.split("OR"))
        .flat_map(|segment| segment.split("and"))
        .flat_map(|segment| segment.split("AND"))
        .map(|s| s.replace("\"", "").replace("(", "").replace(")", ""))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn derive_mask(attr: &str, policy: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(attr.as_bytes());
    hasher.update(policy.as_bytes());
    hasher.finalize().to_vec()
}

fn hash_str(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(&digest[..16])
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abe_round_trip() {
        let attrs = vec!["role=dev".to_string()];
        let user_keys = AbeEngine::generate_user_attr_keys(&attrs);
        let plaintext = b"secret grant".to_vec();
        let ct = AbeEngine::encrypt_for_policy("role=dev", &plaintext).unwrap();
        let decrypted = AbeEngine::decrypt_with_attrs(&ct, &user_keys).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
