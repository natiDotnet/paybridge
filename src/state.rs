use std::sync::Arc;

use sqlx::SqlitePool;

use crate::config::Config;
use crate::verify::Verifier;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
    pub verifier: Arc<Verifier>,
    /// Shared HTTP client for webhook delivery and the verification service.
    pub http: reqwest::Client,
}
