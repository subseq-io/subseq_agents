use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use thiserror::Error;

use subseq_auth::prelude::UserId;

#[derive(Debug, Clone, Copy)]
pub enum KeyManagementOperation {
    List,
    Create,
    Revoke,
}

#[derive(Debug, Clone)]
pub enum KeyManagementAuthorizationDecision {
    Allow,
    Deny(KeyManagementDeny),
}

#[derive(Debug, Clone)]
pub struct KeyManagementDeny {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: &'static str,
}

impl KeyManagementDeny {
    pub fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: "Forbidden",
        }
    }

    pub fn payment_required() -> Self {
        Self {
            status: StatusCode::PAYMENT_REQUIRED,
            code: "payment_required",
            message: "Payment required",
        }
    }
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
    ) -> Result<KeyManagementAuthorizationDecision, KeyManagementAuthorizationError>;
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
    ) -> Result<KeyManagementAuthorizationDecision, KeyManagementAuthorizationError> {
        Ok(KeyManagementAuthorizationDecision::Allow)
    }
}

pub type DynKeyManagementAuthorizer = Arc<dyn KeyManagementAuthorizer>;
