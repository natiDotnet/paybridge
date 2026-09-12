use std::sync::Arc;

use paybridge::{app, config, db, state::AppState, verify, workers};

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,paybridge=debug".into()),
        )
        .init();

    let config = Arc::new(config::Config::from_env());
    let pool = db::create_pool(&config.database_url)
        .await
        .expect("failed to open database");
    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("failed to run migrations");

    let verifier = Arc::new(verify::Verifier::from_config(&config));
    tracing::info!(verifier = ?config.verifier, "verification adapter selected");

    let state = AppState {
        pool,
        config,
        verifier,
        http: reqwest::Client::new(),
    };

    let bind_addr = state.config.bind.clone();
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {bind_addr}: {e}"));

    tokio::spawn(workers::webhook_dispatcher(state.clone()));
    tokio::spawn(workers::expiry_sweeper(state.clone()));

    let app = app::build_app(state);

    tracing::info!("paybridge listening on http://{bind_addr}");
    axum::serve(listener, app).await.expect("server error");
}
