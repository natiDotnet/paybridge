//! Background loops: outbox/webhook dispatcher and checkout expiry sweeper.

use std::time::Duration;

use crate::db;
use crate::ids::now_iso;
use crate::state::AppState;
use crate::webhooks;

pub async fn webhook_dispatcher(state: AppState) {
    let mut ticker = tokio::time::interval(state.config.worker_poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        webhooks::deliver_due_events(&state).await;
    }
}

pub async fn expiry_sweeper(state: AppState) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match db::query(
            "UPDATE checkouts SET status = 'expired', updated_at = ? \
             WHERE status IN ('created', 'pending') AND expires_at <= ?",
        )
        .bind(now_iso())
        .bind(now_iso())
        .execute(&state.pool)
        .await
        {
            Ok(result) if result.rows_affected() > 0 => {
                tracing::info!(expired = result.rows_affected(), "checkouts expired");
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "expiry sweeper failed"),
        }
    }
}
