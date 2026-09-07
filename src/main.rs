//! Entrypoint: environment-driven configuration, then serve forever.

#[tokio::main]
async fn main() -> std::io::Result<()> {
    unidpp_projector::run(unidpp_projector::Config::from_env()).await
}
