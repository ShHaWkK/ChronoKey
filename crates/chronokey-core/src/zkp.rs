use std::convert::TryInto;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use sha2::{Digest, Sha512};

#[derive(Clone, Debug)]
pub struct ZkKeyPair {
    pub secret: Scalar,
    pub public: RistrettoPoint,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ZkProof {
    pub commitment_b64: String,
    pub response_b64: String,
}

pub struct ZkEngine;

impl ZkEngine {
    pub fn generate_keypair() -> ZkKeyPair {
        let secret = Scalar::random(&mut OsRng);
        let public = secret * RISTRETTO_BASEPOINT_POINT;
        ZkKeyPair { secret, public }
    }

    pub fn prove(secret: &Scalar, public: &RistrettoPoint, challenge: &[u8]) -> ZkProof {
        let nonce = Scalar::random(&mut OsRng);
        let commitment_point = nonce * RISTRETTO_BASEPOINT_POINT;
        let challenge_scalar = compute_challenge(&commitment_point, public, challenge);
        let response = nonce + challenge_scalar * secret;
        ZkProof {
            commitment_b64: STANDARD.encode(commitment_point.compress().as_bytes()),
            response_b64: STANDARD.encode(response.to_bytes()),
        }
    }

    pub fn verify(public: &RistrettoPoint, challenge: &[u8], proof: &ZkProof) -> Result<()> {
        let commitment_bytes = STANDARD
            .decode(&proof.commitment_b64)
            .map_err(|_| anyhow!("invalid commitment encoding"))?;
        let response_bytes = STANDARD
            .decode(&proof.response_b64)
            .map_err(|_| anyhow!("invalid response encoding"))?;
        let commitment = CompressedRistretto(
            commitment_bytes
                .try_into()
                .map_err(|_| anyhow!("invalid commitment length"))?,
        )
        .decompress()
        .ok_or_else(|| anyhow!("invalid commitment point"))?;
        let response_scalar = Scalar::from_canonical_bytes(
            response_bytes
                .try_into()
                .map_err(|_| anyhow!("invalid response length"))?,
        )
        .ok_or_else(|| anyhow!("invalid response scalar"))?;
        let challenge_scalar = compute_challenge(&commitment, public, challenge);
        let lhs = response_scalar * RISTRETTO_BASEPOINT_POINT;
        let rhs = commitment + challenge_scalar * public;
        if lhs == rhs {
            Ok(())
        } else {
            Err(anyhow!("ZK proof verification failed"))
        }
    }
}

fn compute_challenge(
    commitment: &RistrettoPoint,
    public: &RistrettoPoint,
    challenge: &[u8],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(commitment.compress().as_bytes());
    hasher.update(public.compress().as_bytes());
    hasher.update(challenge);
    Scalar::from_hash(hasher)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zk_round_trip() {
        let keypair = ZkEngine::generate_keypair();
        let challenge = b"hello";
        let proof = ZkEngine::prove(&keypair.secret, &keypair.public, challenge);
        ZkEngine::verify(&keypair.public, challenge, &proof).unwrap();
    }
}
