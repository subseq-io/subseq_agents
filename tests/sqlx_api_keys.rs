use chrono::{Duration as ChronoDuration, Utc};
use subseq_agents::{ApiKeyStore, ApiKeyStoreError, SqlxApiKeyStore};
use subseq_auth::prelude::UserId;
use uuid::Uuid;

#[path = "support/test_harness.rs"]
mod test_harness;

async fn insert_user(pool: &sqlx::PgPool, user_id: UserId) {
    sqlx::query("INSERT INTO auth.users (id) VALUES ($1)")
        .bind(user_id.0)
        .execute(pool)
        .await
        .expect("insert user");
}

#[tokio::test]
async fn create_key_rejects_past_expiry() {
    let db = test_harness::TestDb::new()
        .await
        .expect("create isolated postgres db");
    db.prepare().await.expect("prepare schema");

    let store = SqlxApiKeyStore::from_pool(&db.pool);
    let user_id = UserId(Uuid::new_v4());
    insert_user(&db.pool, user_id).await;

    let result = store
        .create_key(
            user_id,
            "graph",
            "default",
            Some(Utc::now() - ChronoDuration::minutes(1)),
        )
        .await;
    assert!(matches!(result, Err(ApiKeyStoreError::InvalidExpiry)));

    db.teardown().await.expect("teardown isolated db");
}

#[tokio::test]
async fn expired_key_name_is_reusable() {
    let db = test_harness::TestDb::new()
        .await
        .expect("create isolated postgres db");
    db.prepare().await.expect("prepare schema");

    let store = SqlxApiKeyStore::from_pool(&db.pool);
    let user_id = UserId(Uuid::new_v4());
    insert_user(&db.pool, user_id).await;

    let created = store
        .create_key(
            user_id,
            "graph",
            "default",
            Some(Utc::now() + ChronoDuration::minutes(5)),
        )
        .await
        .expect("first create succeeds");

    sqlx::query(
        "UPDATE agent.mcp_api_keys SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(created.metadata.id)
    .execute(&db.pool)
    .await
    .expect("force key expiry");

    let recreated = store
        .create_key(
            user_id,
            "graph",
            "default",
            Some(Utc::now() + ChronoDuration::minutes(5)),
        )
        .await
        .expect("expired key name should be reusable");

    assert_eq!(recreated.metadata.key_name, "default");

    db.teardown().await.expect("teardown isolated db");
}

#[tokio::test]
async fn revoked_key_cannot_authenticate() {
    let db = test_harness::TestDb::new()
        .await
        .expect("create isolated postgres db");
    db.prepare().await.expect("prepare schema");

    let store = SqlxApiKeyStore::from_pool(&db.pool);
    let user_id = UserId(Uuid::new_v4());
    insert_user(&db.pool, user_id).await;

    let created = store
        .create_key(user_id, "graph", "default", None)
        .await
        .expect("create succeeds");
    store
        .revoke_key(user_id, "graph", "default")
        .await
        .expect("revoke succeeds");

    let auth = store
        .authenticate_key("graph", &created.plaintext_key)
        .await
        .expect("auth query succeeds");
    assert!(auth.is_none());

    db.teardown().await.expect("teardown isolated db");
}
