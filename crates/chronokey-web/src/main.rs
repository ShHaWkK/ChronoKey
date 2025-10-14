use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::{get, post},
    Form, Router,
};
use std::net::SocketAddr;

use chronokey_core::ca::{sign_public_key_in_memory, CaStore};
use chronokey_core::ssh::generate_keypair_in_memory;
use serde::{Deserialize, Serialize};
use chronokey_core::token::{TokenClaims, TokenSigner};
use tera::{Context, Tera};
use tokio::fs;
use tower_http::services::ServeDir;

#[derive(Serialize, Deserialize, Debug)]
struct KeyEntry {
    comment: String,
    public_key: String,
    private_key: String, // Attention: stocker la clé privée n'est pas recommandé en production
}

#[derive(Deserialize)]
struct GenerateParams {
    comment: String,
}

#[derive(Deserialize)]
struct IssueParams {
    public_key: String,
    token: String,
}

#[tokio::main]
async fn main() {
    let tera = Tera::new("crates/chronokey-web/templates/**/*").unwrap();

    let app = Router::new()
        .route("/", get(index))
        .route("/generate", get(generate_form))
        .route("/generate", post(generate_action))
        .route("/issue", get(issue_form))
        .route("/issue", post(issue_action))
        .route("/token", get(token_form))
        .route("/token", post(token_action))
        .route("/list", get(list_keys))
        .nest_service("/static", ServeDir::new("crates/chronokey-web/templates"))
        .with_state(tera);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index(State(tera): State<Tera>) -> Html<String> {
    let context = Context::new();
    Html(tera.render("index.html", &context).unwrap())
}

async fn generate_form(State(tera): State<Tera>) -> Html<String> {
    let context = Context::new();
    Html(tera.render("generate.html", &context).unwrap())
}

async fn issue_form(State(tera): State<Tera>) -> Html<String> {
    let context = Context::new();
    Html(tera.render("issue.html", &context).unwrap())
}

async fn generate_action(
    State(tera): State<Tera>,
    Form(params): Form<GenerateParams>,
) -> impl IntoResponse {
    let (private_key, public_key) = generate_keypair_in_memory(&params.comment).unwrap();

    let new_key = KeyEntry {
        comment: params.comment.clone(),
        public_key: public_key.clone(),
        private_key: private_key.clone(),
    };

    let mut keys: Vec<KeyEntry> = match fs::read_to_string("keys.json").await {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|_| vec![]),
        Err(_) => vec![],
    };

    keys.push(new_key);
    fs::write("keys.json", serde_json::to_string_pretty(&keys).unwrap())
        .await
        .unwrap();

    let mut context = Context::new();
    context.insert("private_key", &private_key);
    context.insert("public_key", &public_key);

    Html(tera.render("generate_result.html", &context).unwrap())
}

async fn issue_action(
    State(tera): State<Tera>,
    Form(params): Form<IssueParams>,
) -> impl IntoResponse {
    let signer = TokenSigner::from_env("CHRONOKEY_HMAC_SECRET").unwrap();
    let grant = signer.verify(&params.token).unwrap();

    if grant.is_expired().unwrap() {
        // Handle expired token
        // For now, just return an error
        return Html("Token expired".to_string());
    }

    let ca_store = CaStore::default().unwrap();
    let ca_key_pair = ca_store.key_pair();

    let principals = grant
        .claims
        .attrs
        .get("principals")
        .map(|s| s.split(',').map(|s| s.to_string()).collect::<Vec<String>>())
        .unwrap_or_default();

    let certificate = sign_public_key_in_memory(
        &ca_key_pair,
        &params.public_key,
        &grant.claims.sub,
        &principals,
        "+1h",
    )
    .unwrap();

    let mut context = Context::new();
    context.insert("certificate", &certificate);

    Html(tera.render("issue_result.html", &context).unwrap())
}

use std::collections::HashMap;

#[derive(Deserialize)]
struct TokenParams {
    subject: String,
    principals: String,
}

async fn token_form(State(tera): State<Tera>) -> Html<String> {
    let context = Context::new();
    Html(tera.render("token.html", &context).unwrap())
}

async fn token_action(
    State(tera): State<Tera>,
    Form(params): Form<TokenParams>,
) -> impl IntoResponse {
    let signer = TokenSigner::from_env("CHRONOKEY_HMAC_SECRET").unwrap();

    let mut attrs = HashMap::new();
    attrs.insert("principals".to_string(), params.principals);

    let claims = TokenClaims::new(&params.subject, 3600, attrs).unwrap();

    let token = signer.sign(&claims).unwrap();

    let mut context = Context::new();
    context.insert("token", &token);

    Html(tera.render("token_result.html", &context).unwrap())
}

async fn list_keys(State(tera): State<Tera>) -> Html<String> {
    let keys: Vec<KeyEntry> = match fs::read_to_string("keys.json").await {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|_| vec![]),
        Err(_) => vec![],
    };

    let mut context = Context::new();
    context.insert("keys", &keys);

    Html(tera.render("list.html", &context).unwrap())
}
