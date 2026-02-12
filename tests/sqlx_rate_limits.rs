use std::time::Duration;

use subseq_agents::{ApiKeyRateLimitConfig, ApiKeyRateLimitStore, SqlxApiKeyRateLimitStore};

#[path = "support/test_harness.rs"]
mod test_harness;

#[tokio::test]
async fn sqlx_rate_limit_blocks_after_threshold() {
    let db = test_harness::TestDb::new()
        .await
        .expect("create isolated postgres db");
    db.prepare().await.expect("prepare schema");

    let store = SqlxApiKeyRateLimitStore::from_pool(&db.pool);
    let config = ApiKeyRateLimitConfig {
        max_failures: 2,
        failure_window: Duration::from_secs(60),
        block_duration: Duration::from_secs(60),
        cleanup_after_requests: 100,
    };
    let key = "key-1";

    store
        .record_failure(key, &config)
        .await
        .expect("record first failure");
    assert!(
        !store
            .is_blocked(key)
            .await
            .expect("check blocked after first failure")
    );

    store
        .record_failure(key, &config)
        .await
        .expect("record second failure");
    assert!(
        store
            .is_blocked(key)
            .await
            .expect("check blocked after second failure")
    );

    db.teardown().await.expect("teardown isolated db");
}

#[tokio::test]
async fn sqlx_rate_limit_resets_on_success() {
    let db = test_harness::TestDb::new()
        .await
        .expect("create isolated postgres db");
    db.prepare().await.expect("prepare schema");

    let store = SqlxApiKeyRateLimitStore::from_pool(&db.pool);
    let config = ApiKeyRateLimitConfig {
        max_failures: 2,
        failure_window: Duration::from_secs(60),
        block_duration: Duration::from_secs(60),
        cleanup_after_requests: 100,
    };
    let key = "key-2";

    store
        .record_failure(key, &config)
        .await
        .expect("record first failure");
    store
        .record_failure(key, &config)
        .await
        .expect("record second failure");
    assert!(
        store
            .is_blocked(key)
            .await
            .expect("check blocked before success")
    );

    store
        .record_success(key)
        .await
        .expect("record success reset");
    assert!(
        !store
            .is_blocked(key)
            .await
            .expect("check unblocked after success")
    );

    db.teardown().await.expect("teardown isolated db");
}
