use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

use subseq_auth::prelude::UserId;

#[derive(Debug, Clone, Copy)]
pub enum KeyManagementOperation {
    List,
    Create,
    Revoke,
}

#[derive(Debug, Error)]
pub enum KeyManagementAuthorizationError {
    #[error("Authorization backend error: {0}")]
    Backend(String),
}

#[async_trait]
pub trait KeyManagementAuthorizer: Send + Sync + 'static {
    async fn authorize(
        &self,
        user_id: UserId,
        mcp_mount_name: &str,
        operation: KeyManagementOperation,
    ) -> Result<bool, KeyManagementAuthorizationError>;
}

#[derive(Debug, Default)]
pub struct AllowAllKeyManagementAuthorizer;

#[async_trait]
impl KeyManagementAuthorizer for AllowAllKeyManagementAuthorizer {
    async fn authorize(
        &self,
        _user_id: UserId,
        _mcp_mount_name: &str,
        _operation: KeyManagementOperation,
    ) -> Result<bool, KeyManagementAuthorizationError> {
        Ok(true)
    }
}

pub type DynKeyManagementAuthorizer = Arc<dyn KeyManagementAuthorizer>;
