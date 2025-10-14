use std::collections::HashSet;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use axum::extract::{ConnectInfo, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use tempfile::NamedTempFile;
use tokio::signal;
use tracing::{error, info};

use chronokey_core::audit::{self, AuditLogEntry};
use chronokey_core::ca::{sign_with_ca, CaKeyPair};
use chronokey_core::config::{load_config, IssuerConfig, ValidityPolicy};
use chronokey_core::token::{GrantToken, TokenSigner};
use chronokey_core::validity::parse_ttl_seconds;
use chronokey_core::zkp::{ZkEngine, ZkProof};

use clap::Parser;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long, default_value = "issuer.toml")]
    config: PathBuf,
}

#[derive(Clone)]
struct AppState {
    ca_key: CaKeyPair,
    token_signer: TokenSigner,
    allowed_principals: Option<HashSet<String>>,
    validity_policy: ValidityPolicy,
}

impl AppState {
    fn from_config(config: IssuerConfig) -> Result<Self> {
        let signer = TokenSigner::from_env(&config.hmac_secret_env)?;
        let ca_key = CaKeyPair::new(config.ca_private_key.clone());
        if !ca_key.private_key.exists() {
            return Err(anyhow!(
                "CA private key {} not found",
                ca_key.private_key.display()
            ));
        }
        Ok(Self {
            ca_key,
            token_signer: signer,
            allowed_principals: config
                .allowed_principals.clone()
                .map(|list| list.into_iter().collect()),
            validity_policy: ValidityPolicy::from_config(&config),
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")

        .init();
    let cli = Cli::parse();
    let config = load_config(&cli.config).with_context(|| "failed to load issuer config")?;
    let bind_addr: SocketAddr = config
        .bind_addr
        .parse()
        .context("invalid bind address in config")?;
    let state = Arc::new(AppState::from_config(config)?);

    let app = Router::new()
        .route("/redeem", post(redeem_handler))
        .route("/redeem_zk", post(redeem_zk_handler))
        .with_state(state.clone());

    info!("starting ChronoKey issuer on {}", bind_addr);

    axum::Server::bind(&bind_addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("issuer server error")?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
    info!("shutdown signal received");
}

async fn redeem_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<RedeemRequest>,
) -> Result<Json<RedeemResponse>, ApiError> {
    let grant = state
        .token_signer
        .verify(&request.token)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if grant
        .is_expired()
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::bad_request("token expired".into()));
    }

    let principals = extract_principals(&grant);
    enforce_principals(&state, &principals)?;

    let validity = derive_validity(&state, &grant)?;

    let cert_b64 = sign_certificate(
        &state.ca_key,
        &request.pubkey_b64,
        &grant,
        &principals,
        &validity,
    )
    .map_err(|e| ApiError::internal(e.to_string()))?;

    audit::emit(AuditLogEntry {
        timestamp: &chrono::Utc::now().to_rfc3339(),
        token_id: &grant.token_id(),
        principals: &principals,
        validity: &validity,
        client_ip: Some(&addr.ip().to_string()),
        chain_hash: None,
    });

    Ok(Json(RedeemResponse { cert_b64 }))
}

async fn redeem_zk_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<RedeemZkRequest>,
) -> Result<Json<RedeemResponse>, ApiError> {
    let proof = request.proof.clone();
    let public_bytes = STANDARD
        .decode(request.public_b64)
        .map_err(|_| ApiError::bad_request("invalid public key encoding".into()))?;
    let public_point = decompress_point(&public_bytes)?;
    let challenge = STANDARD
        .decode(request.challenge_b64)
        .map_err(|_| ApiError::bad_request("invalid challenge encoding".into()))?;
    ZkEngine::verify(&public_point, &challenge, &proof)
        .map_err(|e| ApiError::bad_request(format!("ZK verification failed: {e}")))?;

    redeem_handler(
        State(state),
        ConnectInfo(addr),
        Json(RedeemRequest {
            token: request.token,
            pubkey_b64: request.pubkey_b64,
        }),
    )
    .await
}

fn decompress_point(bytes: &[u8]) -> Result<curve25519_dalek::ristretto::RistrettoPoint, ApiError> {
    use curve25519_dalek::ristretto::CompressedRistretto;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ApiError::bad_request("invalid point length".into()))?;
    CompressedRistretto(array)
        .decompress()
        .ok_or_else(|| ApiError::bad_request("invalid ristretto point".into()))
}

fn extract_principals(grant: &GrantToken) -> Vec<String> {
    if let Some(list) = grant.claims.attrs.get("principals") {
        list.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        vec![grant.claims.sub.clone()]
    }
}

fn enforce_principals(state: &AppState, principals: &[String]) -> Result<(), ApiError> {
    if let Some(allowed) = &state.allowed_principals {
        for principal in principals {
            if !allowed.contains(principal) {
                return Err(ApiError::unauthorised(format!(
                    "principal {principal} not permitted"
                )));
            }
        }
    }
    Ok(())
}

fn derive_validity(state: &AppState, grant: &GrantToken) -> Result<String, ApiError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal("system clock before unix epoch".into()))?
        .as_secs() as i64;
    let remaining = grant.claims.exp - now;
    if remaining <= 0 {
        return Err(ApiError::bad_request("token already expired".into()));
    }
    let capped = remaining.min(parse_policy_validity(&state.validity_policy)?);
    Ok(format!("+{}s", capped))
}

fn parse_policy_validity(policy: &ValidityPolicy) -> Result<i64, ApiError> {
    let trimmed = policy.default_validity.trim_start_matches('+');
    parse_ttl_seconds(trimmed)
        .map_err(|_| ApiError::internal("unable to parse default validity policy".into()))
}

fn sign_certificate(
    ca_key: &CaKeyPair,
    pubkey_b64: &str,
    grant: &GrantToken,
    principals: &[String],
    validity: &str,
) -> Result<String> {
    let pubkey_bytes = STANDARD
        .decode(pubkey_b64)
        .context("invalid pubkey base64")?;
    let mut tmp_pub = NamedTempFile::new().context("failed to create temp public key file")?;
    tmp_pub
        .write_all(&pubkey_bytes)
        .context("failed to write temporary public key")?;
    tmp_pub.flush().context("failed to flush public key file")?;

    let cert_path = tmp_pub.path().with_file_name("issued-cert.pub");
    sign_with_ca(
        ca_key,
        tmp_pub.path(),
        &grant.claims.sub,
        principals,
        validity,
        Some(&cert_path),
    )?;
    let cert_bytes = std::fs::read(&cert_path).context("failed to read issued certificate")?;
    Ok(STANDARD.encode(cert_bytes))
}

#[derive(Debug, serde::Deserialize)]
struct RedeemRequest {
    token: String,
    pubkey_b64: String,
}

#[derive(Debug, serde::Deserialize)]
struct RedeemZkRequest {
    token: String,
    pubkey_b64: String,
    proof: ZkProof,
    public_b64: String,
    challenge_b64: String,
}

#[derive(Debug, serde::Serialize)]
struct RedeemResponse {
    cert_b64: String,
}

#[derive(Debug)]
struct ApiError {
    status: axum::http::StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: String) -> Self {
        Self {
            status: axum::http::StatusCode::BAD_REQUEST,
            message,
        }
    }

    fn unauthorised(message: String) -> Self {
        Self {
            status: axum::http::StatusCode::UNAUTHORIZED,
            message,
        }
    }

    fn internal(message: String) -> Self {
        Self {
            status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            message,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        error!("api error: {}", self.message);
        let body = Json(serde_json::json!({ "error": self.message }));
        (self.status, body).into_response()
    }
}
