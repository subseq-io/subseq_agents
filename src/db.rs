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
use crate::rate_limits::{ApiKeyRateLimitConfig, ApiKeyRateLimitError, ApiKeyRateLimitStore};

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

#[derive(Debug, Clone)]
pub struct SqlxApiKeyRateLimitStore {
    pool: Arc<PgPool>,
}

impl SqlxApiKeyRateLimitStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    pub fn from_pool(pool: &PgPool) -> Self {
        Self {
            pool: Arc::new(pool.clone()),
        }
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

#[async_trait]
impl ApiKeyRateLimitStore for SqlxApiKeyRateLimitStore {
    async fn is_blocked(&self, key: &str) -> Result<bool, ApiKeyRateLimitError> {
        let blocked = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT COALESCE(blocked_until > NOW(), FALSE)
            FROM agent.mcp_api_key_rate_limits
            WHERE rate_limit_key = $1
            "#,
        )
        .bind(key)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(map_sqlx_rate_limit_err)?
        .unwrap_or(false);

        Ok(blocked)
    }

    async fn record_success(&self, key: &str) -> Result<(), ApiKeyRateLimitError> {
        sqlx::query(
            r#"
            DELETE FROM agent.mcp_api_key_rate_limits
            WHERE rate_limit_key = $1
            "#,
        )
        .bind(key)
        .execute(self.pool.as_ref())
        .await
        .map_err(map_sqlx_rate_limit_err)?;
        Ok(())
    }

    async fn record_failure(
        &self,
        key: &str,
        config: &ApiKeyRateLimitConfig,
    ) -> Result<(), ApiKeyRateLimitError> {
        let failure_window_secs = config.failure_window.as_secs() as i64;
        let block_duration_secs = config.block_duration.as_secs() as i64;
        let max_failures = config.max_failures as i64;

        sqlx::query(
            r#"
            INSERT INTO agent.mcp_api_key_rate_limits (
                rate_limit_key,
                failures,
                window_started_at,
                blocked_until,
                updated_at
            )
            VALUES ($1, 1, NOW(), NULL, NOW())
            ON CONFLICT (rate_limit_key) DO UPDATE
            SET
                failures = CASE
                    WHEN agent.mcp_api_key_rate_limits.window_started_at <= (NOW() - make_interval(secs => $2))
                    THEN 1
                    ELSE agent.mcp_api_key_rate_limits.failures + 1
                END,
                window_started_at = CASE
                    WHEN agent.mcp_api_key_rate_limits.window_started_at <= (NOW() - make_interval(secs => $2))
                    THEN NOW()
                    ELSE agent.mcp_api_key_rate_limits.window_started_at
                END,
                blocked_until = CASE
                    WHEN (
                        CASE
                            WHEN agent.mcp_api_key_rate_limits.window_started_at <= (NOW() - make_interval(secs => $2))
                            THEN 1
                            ELSE agent.mcp_api_key_rate_limits.failures + 1
                        END
                    ) >= $3
                    THEN NOW() + make_interval(secs => $4)
                    ELSE NULL
                END,
                updated_at = NOW()
            "#,
        )
        .bind(key)
        .bind(failure_window_secs)
        .bind(max_failures)
        .bind(block_duration_secs)
        .execute(self.pool.as_ref())
        .await
        .map_err(map_sqlx_rate_limit_err)?;

        Ok(())
    }

    async fn cleanup_expired(
        &self,
        config: &ApiKeyRateLimitConfig,
    ) -> Result<(), ApiKeyRateLimitError> {
        let cleanup_horizon_secs =
            (config.failure_window + config.block_duration + config.block_duration).as_secs()
                as i64;
        sqlx::query(
            r#"
            DELETE FROM agent.mcp_api_key_rate_limits
            WHERE (
                blocked_until IS NULL
                AND window_started_at <= NOW() - make_interval(secs => $1)
            ) OR (
                blocked_until IS NOT NULL
                AND blocked_until <= NOW() - make_interval(secs => $1)
            )
            "#,
        )
        .bind(cleanup_horizon_secs)
        .execute(self.pool.as_ref())
        .await
        .map_err(map_sqlx_rate_limit_err)?;
        Ok(())
    }
}

fn map_sqlx_err(err: sqlx::Error) -> ApiKeyStoreError {
    ApiKeyStoreError::Internal(err.to_string())
}

fn map_sqlx_rate_limit_err(err: sqlx::Error) -> ApiKeyRateLimitError {
    ApiKeyRateLimitError::Backend(err.to_string())
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
