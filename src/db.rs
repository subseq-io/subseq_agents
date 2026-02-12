use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use subseq_auth::prelude::UserId;

use crate::api_keys::{
    ApiKeyAuthResult, ApiKeyMetadata, ApiKeyStore, ApiKeyStoreError, CreatedApiKey,
    GeneratedApiKey, ToolActor, generate_api_key, parse_presented_key, validate_expires_at,
    validate_key_name, verify_secret_hash,
};

pub static MIGRATOR: Lazy<Migrator> = Lazy::new(|| {
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.set_ignore_missing(true);
    migrator
});

pub async fn create_agent_tables(pool: &PgPool) -> Result<(), MigrateError> {
    MIGRATOR.run(pool).await
}

#[derive(Debug, Clone)]
pub struct SqlxApiKeyStore {
    pool: Arc<PgPool>,
}

impl SqlxApiKeyStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    pub fn from_pool(pool: &PgPool) -> Self {
        Self {
            pool: Arc::new(pool.clone()),
        }
    }

    pub fn pool(&self) -> Arc<PgPool> {
        Arc::clone(&self.pool)
    }
}

#[derive(Debug, Clone, FromRow)]
struct ApiKeyRow {
    id: Uuid,
    user_id: Uuid,
    mcp_mount_name: String,
    key_name: String,
    secret_hash: String,
    secret_prefix: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl ApiKeyRow {
    fn to_metadata(&self) -> ApiKeyMetadata {
        ApiKeyMetadata {
            id: self.id,
            key_name: self.key_name.clone(),
            created_at: self.created_at,
            last_used_at: self.last_used_at,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
            secret_prefix: self.secret_prefix.clone(),
        }
    }
}

#[async_trait]
impl ApiKeyStore for SqlxApiKeyStore {
    async fn list_keys(
        &self,
        user_id: UserId,
        mcp_mount_name: &str,
    ) -> Result<Vec<ApiKeyMetadata>, ApiKeyStoreError> {
        let rows = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            SELECT
                id,
                user_id,
                mcp_mount_name,
                key_name,
                secret_hash,
                secret_prefix,
                created_at,
                last_used_at,
                expires_at,
                revoked_at
            FROM agent.mcp_api_keys
            WHERE user_id = $1
              AND mcp_mount_name = $2
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at ASC
            "#,
        )
        .bind(user_id.0)
        .bind(mcp_mount_name)
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(map_sqlx_err)?;

        Ok(rows.into_iter().map(|row| row.to_metadata()).collect())
    }

    async fn create_key(
        &self,
        user_id: UserId,
        mcp_mount_name: &str,
        key_name: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<CreatedApiKey, ApiKeyStoreError> {
        let key_name = validate_key_name(key_name)?;
        validate_expires_at(expires_at)?;

        sqlx::query(
            r#"
            UPDATE agent.mcp_api_keys
            SET revoked_at = NOW()
            WHERE user_id = $1
              AND mcp_mount_name = $2
              AND key_name = $3
              AND revoked_at IS NULL
              AND expires_at IS NOT NULL
              AND expires_at <= NOW()
            "#,
        )
        .bind(user_id.0)
        .bind(mcp_mount_name)
        .bind(key_name)
        .execute(self.pool.as_ref())
        .await
        .map_err(map_sqlx_err)?;

        let GeneratedApiKey {
            id,
            plaintext_key,
            secret_hash,
            secret_prefix,
            ..
        } = generate_api_key(Uuid::new_v4())?;

        let row = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            INSERT INTO agent.mcp_api_keys (
                id,
                user_id,
                mcp_mount_name,
                key_name,
                secret_hash,
                secret_prefix,
                expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING
                id,
                user_id,
                mcp_mount_name,
                key_name,
                secret_hash,
                secret_prefix,
                created_at,
                last_used_at,
                expires_at,
                revoked_at
            "#,
        )
        .bind(id)
        .bind(user_id.0)
        .bind(mcp_mount_name)
        .bind(key_name)
        .bind(secret_hash)
        .bind(secret_prefix)
        .bind(expires_at)
        .fetch_one(self.pool.as_ref())
        .await
        .map_err(|err| match conflict_on_unique(&err) {
            Some(()) => ApiKeyStoreError::Conflict,
            None => map_sqlx_err(err),
        })?;

        Ok(CreatedApiKey {
            metadata: row.to_metadata(),
            plaintext_key,
        })
    }

    async fn revoke_key(
        &self,
        user_id: UserId,
        mcp_mount_name: &str,
        key_name: &str,
    ) -> Result<ApiKeyMetadata, ApiKeyStoreError> {
        let row = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            UPDATE agent.mcp_api_keys
            SET revoked_at = NOW()
            WHERE user_id = $1
              AND mcp_mount_name = $2
              AND key_name = $3
              AND revoked_at IS NULL
            RETURNING
                id,
                user_id,
                mcp_mount_name,
                key_name,
                secret_hash,
                secret_prefix,
                created_at,
                last_used_at,
                expires_at,
                revoked_at
            "#,
        )
        .bind(user_id.0)
        .bind(mcp_mount_name)
        .bind(key_name)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(map_sqlx_err)?;

        let Some(row) = row else {
            return Err(ApiKeyStoreError::NotFound);
        };

        Ok(row.to_metadata())
    }

    async fn authenticate_key(
        &self,
        mcp_mount_name: &str,
        presented_key: &str,
    ) -> Result<ApiKeyAuthResult, ApiKeyStoreError> {
        let (key_id, secret) = match parse_presented_key(presented_key) {
            Some(parts) => parts,
            None => return Ok(None),
        };

        let mut tx = self.pool.begin().await.map_err(map_sqlx_err)?;
        let row = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            SELECT
                id,
                user_id,
                mcp_mount_name,
                key_name,
                secret_hash,
                secret_prefix,
                created_at,
                last_used_at,
                expires_at,
                revoked_at
            FROM agent.mcp_api_keys
            WHERE id = $1
              AND mcp_mount_name = $2
            FOR UPDATE
            "#,
        )
        .bind(key_id)
        .bind(mcp_mount_name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx_err)?;

        let Some(row) = row else {
            return Ok(None);
        };

        if row.revoked_at.is_some() {
            return Ok(None);
        }
        if row
            .expires_at
            .is_some_and(|expires_at| expires_at <= Utc::now())
        {
            return Ok(None);
        }
        if !verify_secret_hash(&row.secret_hash, secret)? {
            return Ok(None);
        }

        let updated_row = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            UPDATE agent.mcp_api_keys
            SET last_used_at = NOW()
            WHERE id = $1
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > NOW())
            RETURNING
                id,
                user_id,
                mcp_mount_name,
                key_name,
                secret_hash,
                secret_prefix,
                created_at,
                last_used_at,
                expires_at,
                revoked_at
            "#,
        )
        .bind(row.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx_err)?;

        let Some(updated_row) = updated_row else {
            tx.rollback().await.map_err(map_sqlx_err)?;
            return Ok(None);
        };

        tx.commit().await.map_err(map_sqlx_err)?;

        Ok(Some(ToolActor {
            user_id: UserId(updated_row.user_id),
            mcp_mount_name: updated_row.mcp_mount_name,
            api_key_id: updated_row.id,
            api_key_name: updated_row.key_name,
        }))
    }
}

fn map_sqlx_err(err: sqlx::Error) -> ApiKeyStoreError {
    ApiKeyStoreError::Internal(err.to_string())
}

fn conflict_on_unique(err: &sqlx::Error) -> Option<()> {
    let sqlx::Error::Database(db_err) = err else {
        return None;
    };
    if db_err.code().as_deref() == Some("23505") {
        Some(())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use chrono::Duration as ChronoDuration;
    use sqlx::PgPool;
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    async fn setup_test_db(pool: &PgPool) {
        sqlx::query("CREATE SCHEMA IF NOT EXISTS auth")
            .execute(pool)
            .await
            .expect("create auth schema");
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS auth.users (
                id uuid PRIMARY KEY
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("create auth.users");
        create_agent_tables(pool)
            .await
            .expect("run agent migrations");
    }

    async fn insert_user(pool: &PgPool, user_id: UserId) {
        sqlx::query("INSERT INTO auth.users (id) VALUES ($1)")
            .bind(user_id.0)
            .execute(pool)
            .await
            .expect("insert user");
    }

    async fn test_pool() -> Option<PgPool> {
        let database_url = match env::var("DATABASE_URL") {
            Ok(value) => value,
            Err(_) => return None,
        };

        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("connect postgres for integration test");
        Some(pool)
    }

    #[tokio::test]
    async fn create_key_rejects_past_expiry() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping SQLx integration test: DATABASE_URL is not set");
            return;
        };
        setup_test_db(&pool).await;
        let store = SqlxApiKeyStore::from_pool(&pool);
        let user_id = UserId(Uuid::new_v4());
        insert_user(&pool, user_id).await;

        let result = store
            .create_key(
                user_id,
                "graph",
                "default",
                Some(Utc::now() - ChronoDuration::minutes(1)),
            )
            .await;
        assert!(matches!(result, Err(ApiKeyStoreError::InvalidExpiry)));
    }

    #[tokio::test]
    async fn expired_key_name_is_reusable() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping SQLx integration test: DATABASE_URL is not set");
            return;
        };
        setup_test_db(&pool).await;
        let store = SqlxApiKeyStore::from_pool(&pool);
        let user_id = UserId(Uuid::new_v4());
        insert_user(&pool, user_id).await;

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
        .execute(&pool)
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
    }

    #[tokio::test]
    async fn revoked_key_cannot_authenticate() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping SQLx integration test: DATABASE_URL is not set");
            return;
        };
        setup_test_db(&pool).await;
        let store = SqlxApiKeyStore::from_pool(&pool);
        let user_id = UserId(Uuid::new_v4());
        insert_user(&pool, user_id).await;

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
    }
}
