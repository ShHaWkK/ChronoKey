use chronokey_core::token::{TokenClaims, TokenSigner};
use clap::Parser;
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    subject: String,

    #[arg(long)]
    principals: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let signer = TokenSigner::from_env("CHRONOKEY_HMAC_SECRET").unwrap();

    let mut attrs = HashMap::new();
    attrs.insert("principals".to_string(), args.principals);

    let claims = TokenClaims::new(&args.subject, 3600, attrs).unwrap();

    let token = signer.sign(&claims).unwrap();

    println!("{}", token);
}
