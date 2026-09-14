use std::sync::Arc;

use crate::db::Pool;

use crate::config::Config;
use crate::verify::Verifier;

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool,
    pub config: Arc<Config>,
    pub verifier: Arc<Verifier>,
    /// Shared HTTP client for webhook delivery and the verification service.
    pub http: reqwest::Client,
}
