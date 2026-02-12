use std::collections::HashMap;
use std::sync::Arc;

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
    rand_core::RngCore,
};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

use subseq_auth::prelude::UserId;

pub(crate) const API_KEY_PREFIX: &str = "mcpk_";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolActor {
    pub user_id: UserId,
    pub mcp_mount_name: String,
    pub api_key_id: Uuid,
    pub api_key_name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyMetadata {
    pub id: Uuid,
    pub key_name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub secret_prefix: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedApiKey {
    pub metadata: ApiKeyMetadata,
    pub plaintext_key: String,
}

pub type ApiKeyAuthResult = Option<ToolActor>;

pub(crate) struct GeneratedApiKey {
    pub id: Uuid,
    pub plaintext_key: String,
    pub secret_hash: String,
    pub secret_prefix: String,
}

#[derive(Debug, Error)]
pub enum ApiKeyStoreError {
    #[error("Invalid key name")]
    InvalidKeyName,
    #[error("Invalid expiry")]
    InvalidExpiry,
    #[error("Key already exists")]
    Conflict,
    #[error("Unknown key")]
    NotFound,
    #[error("Internal error: {0}")]
    Internal(String),
}

#[async_trait]
pub trait ApiKeyStore: Send + Sync + 'static {
    async fn list_keys(
        &self,
        user_id: UserId,
        mcp_mount_name: &str,
    ) -> Result<Vec<ApiKeyMetadata>, ApiKeyStoreError>;

    async fn create_key(
        &self,
        user_id: UserId,
        mcp_mount_name: &str,
        key_name: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<CreatedApiKey, ApiKeyStoreError>;

    async fn revoke_key(
        &self,
        user_id: UserId,
        mcp_mount_name: &str,
        key_name: &str,
    ) -> Result<ApiKeyMetadata, ApiKeyStoreError>;

    async fn authenticate_key(
        &self,
        mcp_mount_name: &str,
        presented_key: &str,
    ) -> Result<ApiKeyAuthResult, ApiKeyStoreError>;
}

#[derive(Debug, Clone)]
pub struct InMemoryApiKeyStore {
    inner: Arc<RwLock<HashMap<Uuid, StoredApiKey>>>,
}

impl InMemoryApiKeyStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryApiKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct StoredApiKey {
    id: Uuid,
    user_id: UserId,
    mcp_mount_name: String,
    key_name: String,
    secret_hash: String,
    secret_prefix: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl StoredApiKey {
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
impl ApiKeyStore for InMemoryApiKeyStore {
    async fn list_keys(
        &self,
        user_id: UserId,
        mcp_mount_name: &str,
    ) -> Result<Vec<ApiKeyMetadata>, ApiKeyStoreError> {
        let now = Utc::now();
        let guard = self.inner.read().await;
        let mut keys = guard
            .values()
            .filter(|row| row.user_id == user_id)
            .filter(|row| row.mcp_mount_name == mcp_mount_name)
            .filter(|row| row.revoked_at.is_none())
            .filter(|row| row.expires_at.is_none_or(|expires_at| expires_at > now))
            .map(StoredApiKey::to_metadata)
            .collect::<Vec<_>>();
        keys.sort_by_key(|row| row.created_at);
        Ok(keys)
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

        let mut guard = self.inner.write().await;
        let now = Utc::now();
        if guard.values().any(|row| {
            row.user_id == user_id
                && row.mcp_mount_name == mcp_mount_name
                && row.key_name == key_name
                && row.revoked_at.is_none()
                && row.expires_at.is_none_or(|expires_at| expires_at > now)
        }) {
            return Err(ApiKeyStoreError::Conflict);
        }

        let GeneratedApiKey {
            id,
            plaintext_key,
            secret_hash,
            secret_prefix,
            ..
        } = generate_api_key(Uuid::new_v4())?;

        let row = StoredApiKey {
            id,
            user_id,
            mcp_mount_name: mcp_mount_name.to_string(),
            key_name: key_name.to_string(),
            secret_hash,
            secret_prefix,
            created_at: Utc::now(),
            last_used_at: None,
            expires_at,
            revoked_at: None,
        };

        let metadata = row.to_metadata();
        guard.insert(id, row);

        Ok(CreatedApiKey {
            metadata,
            plaintext_key,
        })
    }

    async fn revoke_key(
        &self,
        user_id: UserId,
        mcp_mount_name: &str,
        key_name: &str,
    ) -> Result<ApiKeyMetadata, ApiKeyStoreError> {
        let mut guard = self.inner.write().await;
        let row = guard
            .values_mut()
            .find(|row| {
                row.user_id == user_id
                    && row.mcp_mount_name == mcp_mount_name
                    && row.key_name == key_name
                    && row.revoked_at.is_none()
            })
            .ok_or(ApiKeyStoreError::NotFound)?;

        row.revoked_at = Some(Utc::now());
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

        let mut guard = self.inner.write().await;
        let row = match guard.get_mut(&key_id) {
            Some(row) => row,
            None => return Ok(None),
        };

        if row.mcp_mount_name != mcp_mount_name {
            return Ok(None);
        }
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

        row.last_used_at = Some(Utc::now());
        Ok(Some(ToolActor {
            user_id: row.user_id,
            mcp_mount_name: row.mcp_mount_name.clone(),
            api_key_id: row.id,
            api_key_name: row.key_name.clone(),
        }))
    }
}

pub(crate) fn parse_presented_key(presented_key: &str) -> Option<(Uuid, &str)> {
    let token = presented_key.trim();
    let token = token.strip_prefix(API_KEY_PREFIX)?;
    let (id, secret) = token.split_once('.')?;
    let id = Uuid::parse_str(id).ok()?;
    if secret.is_empty() {
        return None;
    }
    Some((id, secret))
}

pub(crate) fn generate_api_key(id: Uuid) -> Result<GeneratedApiKey, ApiKeyStoreError> {
    let mut secret_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let plaintext_key = format!("{API_KEY_PREFIX}{id}.{secret}");
    let secret_prefix = secret.chars().take(8).collect::<String>();

    let salt = SaltString::generate(&mut OsRng);
    let secret_hash = Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|err| ApiKeyStoreError::Internal(err.to_string()))?
        .to_string();

    Ok(GeneratedApiKey {
        id,
        plaintext_key,
        secret_hash,
        secret_prefix,
    })
}

pub(crate) fn verify_secret_hash(
    secret_hash: &str,
    presented_secret: &str,
) -> Result<bool, ApiKeyStoreError> {
    let parsed_hash = PasswordHash::new(secret_hash)
        .map_err(|err| ApiKeyStoreError::Internal(err.to_string()))?;
    Ok(Argon2::default()
        .verify_password(presented_secret.as_bytes(), &parsed_hash)
        .is_ok())
}

pub(crate) fn validate_key_name(key_name: &str) -> Result<&str, ApiKeyStoreError> {
    let key_name = key_name.trim();
    if key_name.is_empty() || key_name.len() > 64 {
        return Err(ApiKeyStoreError::InvalidKeyName);
    }

    let mut chars = key_name.chars();
    let first = chars.next().ok_or(ApiKeyStoreError::InvalidKeyName)?;
    if !first.is_ascii_alphanumeric() {
        return Err(ApiKeyStoreError::InvalidKeyName);
    }

    if chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.') {
        Ok(key_name)
    } else {
        Err(ApiKeyStoreError::InvalidKeyName)
    }
}

pub(crate) fn validate_expires_at(
    expires_at: Option<DateTime<Utc>>,
) -> Result<(), ApiKeyStoreError> {
    if expires_at.is_some_and(|value| value <= Utc::now()) {
        return Err(ApiKeyStoreError::InvalidExpiry);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn key_lifecycle_roundtrip() {
        let store = InMemoryApiKeyStore::new();
        let user_id = UserId(Uuid::new_v4());

        let created = store
            .create_key(user_id, "graph", "default", None)
            .await
            .expect("create should succeed");

        let list = store
            .list_keys(user_id, "graph")
            .await
            .expect("list should succeed");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].key_name, "default");

        let auth = store
            .authenticate_key("graph", &created.plaintext_key)
            .await
            .expect("auth should succeed");
        let actor = auth.expect("valid key should authenticate");
        assert_eq!(actor.user_id, user_id);
        assert_eq!(actor.api_key_name, "default");

        let _revoked = store
            .revoke_key(user_id, "graph", "default")
            .await
            .expect("revoke should succeed");

        let auth = store
            .authenticate_key("graph", &created.plaintext_key)
            .await
            .expect("auth should succeed");
        assert!(auth.is_none(), "revoked key should not authenticate");
    }

    #[tokio::test]
    async fn mount_scope_is_enforced() {
        let store = InMemoryApiKeyStore::new();
        let user_id = UserId(Uuid::new_v4());

        let created = store
            .create_key(user_id, "graph", "default", None)
            .await
            .expect("create should succeed");

        let auth = store
            .authenticate_key("tasks", &created.plaintext_key)
            .await
            .expect("auth should succeed");
        assert!(auth.is_none(), "mount mismatch should fail auth");
    }

    #[test]
    fn key_name_validation_enforces_charset_and_length() {
        assert!(validate_key_name("alpha").is_ok());
        assert!(validate_key_name("alpha-1._beta").is_ok());
        assert!(validate_key_name(" alpha ").is_ok());
        assert!(validate_key_name("").is_err());
        assert!(validate_key_name(" ").is_err());
        assert!(validate_key_name("-alpha").is_err());
        assert!(validate_key_name("a/b").is_err());
        assert!(validate_key_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn expiry_validation_rejects_past_expiry() {
        assert!(validate_expires_at(Some(Utc::now() - chrono::Duration::seconds(1))).is_err());
        assert!(validate_expires_at(Some(Utc::now() + chrono::Duration::seconds(1))).is_ok());
        assert!(validate_expires_at(None).is_ok());
    }
}
