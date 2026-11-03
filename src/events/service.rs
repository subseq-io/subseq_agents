//! Reusable native MCP Events core. Does not assemble servers or spawn workers.
use super::{
    crypto::{self as event_crypto, SecretBox},
    store::{self as db, Subscription},
    webhooks::{EventFuture, WebhookTransport, callback_url},
};
use anyhow::{Context, ensure};
use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct Principal {
    pub owner: Uuid,
    pub key: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedEvent {
    pub event_id: String,
    pub user_id: Uuid,
    pub name: String,
    pub timestamp: DateTime<Utc>,
    pub data: Value,
}
/// Service-specific catalog, validation, and resource access. Filters use JSON containment equality.
/// Implementations must reject unsupported event names and fields and enforce payload schemas.
pub trait EventPolicy: Send + Sync {
    fn catalog(&self) -> Vec<Value>;
    fn validate_subscription(&self, name: &str, args: &Value) -> anyhow::Result<()>;
    fn validate_event(&self, event: &PublishedEvent) -> anyhow::Result<()>;
    fn event_access_arguments(&self, data: &Value) -> anyhow::Result<Value>;
    fn authorize<'a>(&'a self, owner: Uuid, args: &'a Value) -> EventFuture<'a, bool>;
}
pub struct EventServiceConfig {
    pub mount_name: String,
    pub encryption_key_id: String,
    pub encryption_keys: BTreeMap<String, String>,
}
pub struct EventService {
    pool: Arc<PgPool>,
    mount_name: String,
    vault: SecretBox,
    policy: Arc<dyn EventPolicy>,
    transport: Arc<dyn WebhookTransport>,
    verifying: Mutex<HashMap<String, std::sync::Weak<Mutex<()>>>>,
    verified: Mutex<HashMap<String, Instant>>,
}
impl EventService {
    pub fn new(
        pool: Arc<PgPool>,
        config: EventServiceConfig,
        policy: Arc<dyn EventPolicy>,
        transport: Arc<dyn WebhookTransport>,
    ) -> anyhow::Result<Self> {
        ensure!(
            !config.mount_name.is_empty()
                && config.mount_name.len() <= 64
                && config
                    .mount_name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
            "Invalid event mount name"
        );
        let vault = SecretBox {
            current: config.encryption_key_id,
            keys: config.encryption_keys,
        };
        vault.validate()?;
        Ok(Self {
            pool,
            mount_name: config.mount_name,
            vault,
            policy,
            transport,
            verifying: Mutex::new(HashMap::new()),
            verified: Mutex::new(HashMap::new()),
        })
    }
    fn subscription_id(&self, owner: Uuid, name: &str, url: &str, args: &Value) -> String {
        // Preserve identities and AEAD associated data of existing router subscriptions.
        let owner = if self.mount_name == "router" {
            owner.to_string()
        } else {
            format!("mount:{}:{owner}", self.mount_name)
        };
        event_crypto::identity(&owner, name, url, args)
    }
    pub async fn maintain(&self) -> anyhow::Result<()> {
        db::sweep(&self.pool, &self.mount_name).await
    }
    pub async fn authorize(&self, principal: Principal, args: &Value) -> anyhow::Result<()> {
        ensure!(
            db::principal_active(&self.pool, principal.owner, principal.key, &self.mount_name)
                .await?,
            "Reconnect your account to continue."
        );
        ensure!(
            self.policy.authorize(principal.owner, args).await?,
            "You don't have access to this resource."
        );
        Ok(())
    }
    pub async fn dispatch(
        &self,
        principal: Principal,
        method: &str,
        params: Value,
    ) -> anyhow::Result<Value> {
        match method {
            "events/list" => {
                ensure!(
                    params.get("cursor").is_none_or(Value::is_null),
                    "This event catalog has no additional pages."
                );
                self.authorize(principal, &json!({})).await?;
                Ok(json!({"events":self.policy.catalog()}))
            }
            "events/subscribe" => self.subscribe(principal, params).await,
            "events/unsubscribe" => {
                let (name, args, url) = subscription_identity(&params)?;
                self.policy.validate_subscription(name, &args)?;
                // Ownership is local; permit cleanup even after harness resource access was removed.
                ensure!(
                    db::principal_active(
                        &self.pool,
                        principal.owner,
                        principal.key,
                        &self.mount_name
                    )
                    .await?,
                    "Reconnect your account to continue."
                );
                let id = self.subscription_id(principal.owner, name, url, &args);
                db::stop(&self.pool, &id, principal.owner).await?;
                Ok(json!({}))
            }
            _ => anyhow::bail!("This event method is not supported."),
        }
    }
    async fn subscribe(&self, principal: Principal, params: Value) -> anyhow::Result<Value> {
        let (name, args, url) = subscription_identity(&params)?;
        self.policy.validate_subscription(name, &args)?;
        ensure!(
            params.get("cursor").is_none_or(Value::is_null),
            "Event replay is unavailable. Use the source service's read tools to recover missed work."
        );
        let ttl = subscription_ttl(&params)?;
        let secret = params
            .pointer("/delivery/secret")
            .and_then(Value::as_str)
            .context("A signing secret is required.")?;
        event_crypto::decode_secret(secret)?;
        callback_url(url)?;
        self.authorize(principal, &args).await?;
        let id = self.subscription_id(principal.owner, name, url, &args);
        let lock = {
            let mut locks = self.verifying.lock().await;
            locks.retain(|_, v| v.strong_count() > 0);
            if let Some(lock) = locks.get(&id).and_then(std::sync::Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(Mutex::new(()));
                locks.insert(id.clone(), Arc::downgrade(&lock));
                lock
            }
        };
        let _guard = lock.lock().await;
        let context = format!("{}/{}", principal.owner, id);
        let sub = Subscription {
            id: id.clone(),
            mount_name: self.mount_name.clone(),
            owner_id: principal.owner,
            api_key_id: principal.key,
            name: name.into(),
            arguments: args,
            callback_url: url.into(),
            secret: self.vault.seal(&context, secret)?,
            secret_fingerprint: event_crypto::identity(
                &principal.owner.to_string(),
                "signing-key",
                "",
                &json!(secret),
            ),
            previous_secret: None,
            rotate_until: None,
            expires_at: Utc::now() + chrono::Duration::milliseconds(ttl),
            state: "verifying".into(),
            generation: 1,
            verify_until: None,
        };
        let granted_expiry = sub.expires_at;
        let sub = db::reserve(&self.pool, &sub).await?;
        let cache_id = event_crypto::identity(
            &principal.owner.to_string(),
            "callback",
            url,
            &json!(secret),
        );
        let cached = {
            let mut cache = self.verified.lock().await;
            cache.retain(|_, t| t.elapsed() < Duration::from_secs(300));
            cache.contains_key(&cache_id)
        };
        let verified = if cached {
            Ok(())
        } else {
            self.verify(&sub, secret).await
        };
        if verified.is_err() {
            db::finish_verification(&self.pool, &id, sub.generation, false).await?;
            anyhow::bail!(
                "Callback verification failed. Check your callback endpoint and try again."
            );
        }
        // Recheck access after network verification, and fence a concurrent unsubscribe.
        if let Err(error) = self.authorize(principal, &sub.arguments).await {
            db::finish_verification(&self.pool, &id, sub.generation, false).await?;
            return Err(error);
        }
        ensure!(
            db::finish_verification(&self.pool, &id, sub.generation, true).await?,
            "Subscription changed while verifying. Please retry."
        );
        {
            let mut cache = self.verified.lock().await;
            if cache.len() >= 10000 {
                cache.clear();
            }
            cache.insert(cache_id, Instant::now());
        }
        Ok(json!({"id":id,"refreshBefore":granted_expiry,"cursor":null,"truncated":false}))
    }
    async fn verify(&self, sub: &Subscription, secret: &str) -> anyhow::Result<()> {
        let challenge = Uuid::new_v4().to_string();
        let body = serde_json::to_vec(&json!({"type":"verification","challenge":challenge}))?;
        let response = self
            .send(
                sub,
                &format!("verification_{}", Uuid::new_v4()),
                body,
                secret,
                None,
            )
            .await?;
        ensure!(
            response.status.is_success(),
            "Callback rejected verification"
        );
        let value: Value = serde_json::from_slice(&response.body)?;
        let echo = value
            .get("challenge")
            .and_then(Value::as_str)
            .context("Missing challenge")?;
        ensure!(
            event_crypto::constant_eq(challenge.as_bytes(), echo.as_bytes()),
            "Callback challenge mismatch"
        );
        Ok(())
    }
    fn send<'a>(
        &'a self,
        sub: &'a Subscription,
        id: &'a str,
        body: Vec<u8>,
        secret: &'a str,
        previous: Option<&'a str>,
    ) -> EventFuture<'a, super::webhooks::WebhookResponse> {
        Box::pin(async move {
            ensure!(body.len() <= 262144, "Event is too large");
            let timestamp = Utc::now().timestamp();
            let mut signature = event_crypto::sign(secret, id, timestamp, &body)?;
            if let Some(old) = previous {
                if old != secret {
                    signature.push(' ');
                    signature.push_str(&event_crypto::sign(old, id, timestamp, &body)?);
                }
            }
            let mut headers = HeaderMap::new();
            headers.insert("content-type", HeaderValue::from_static("application/json"));
            headers.insert("webhook-id", HeaderValue::from_str(id)?);
            headers.insert(
                "webhook-timestamp",
                HeaderValue::from_str(&timestamp.to_string())?,
            );
            headers.insert("webhook-signature", HeaderValue::from_str(&signature)?);
            headers.insert("x-mcp-subscription-id", HeaderValue::from_str(&sub.id)?);
            tokio::time::timeout(
                Duration::from_secs(12),
                self.transport.post(&sub.callback_url, headers, body),
            )
            .await?
        })
    }
    pub async fn publish(&self, producer_id: &str, event: PublishedEvent) -> anyhow::Result<Uuid> {
        self.policy.validate_event(&event)?;
        let args = self.policy.event_access_arguments(&event.data)?;
        ensure!(
            db::user_active(&self.pool, event.user_id).await?
                && self.policy.authorize(event.user_id, &args).await?,
            "The recipient does not have access to this resource."
        );
        db::publish(
            &self.pool,
            &self.mount_name,
            producer_id,
            &event.event_id,
            event.user_id,
            &event.name,
            &event.data,
            event.timestamp,
        )
        .await
    }
    pub async fn deliver_once(&self) -> anyhow::Result<bool> {
        let Some(delivery) = db::claim(&self.pool, &self.mount_name).await? else {
            return Ok(false);
        };
        let outcome = self.deliver(&delivery).await;
        let (state, status) = match outcome {
            Ok((status, _)) if (200..300).contains(&status) => ("delivered", Some(status)),
            Ok((410, generation)) => {
                if db::stop_generation(&self.pool, &delivery.subscription_id, generation).await? {
                    ("cancelled", Some(410))
                } else {
                    // Do not retry a 410 delivery, but preserve a newer verified grant.
                    ("dead", Some(410))
                }
            }
            Ok((0, _)) => ("cancelled", None),
            Ok((status, _))
                if status == 413
                    || ((400..500).contains(&status) && status != 408 && status != 429) =>
            {
                ("dead", Some(status))
            }
            Ok((status, _)) => (
                if delivery.attempts >= 8 {
                    "dead"
                } else {
                    "pending"
                },
                Some(status),
            ),
            Err(_) => (
                if delivery.attempts >= 8 {
                    "dead"
                } else {
                    "pending"
                },
                None,
            ),
        };
        let jitter = (Uuid::new_v4().as_u128() % 5) as i32;
        let delay = (5i32.saturating_mul(1i32 << delivery.attempts.min(7))) + jitter;
        db::finish_delivery(&self.pool, &delivery, state, status, delay).await?;
        tracing::info!(event_id=%delivery.event_id,subscription_id=%delivery.subscription_id,attempt=delivery.attempts,state,status,"MCP event delivery attempt");
        Ok(true)
    }
    async fn deliver(&self, d: &db::Delivery) -> anyhow::Result<(u16, i64)> {
        let Some(sub) = db::get(&self.pool, &d.subscription_id).await? else {
            return Ok((0, 0));
        };
        if sub.state == "verifying"
            || (sub.expires_at <= Utc::now() && sub.verify_until.is_some_and(|t| t > Utc::now()))
        {
            anyhow::bail!("Subscription verification is pending");
        }
        if sub.state != "active" || sub.expires_at <= Utc::now() {
            return Ok((0, 0));
        }
        if !db::principal_active(&self.pool, sub.owner_id, sub.api_key_id, &self.mount_name).await?
            || !self.policy.authorize(sub.owner_id, &sub.arguments).await?
        {
            if db::stop_generation(&self.pool, &sub.id, sub.generation).await? {
                return Ok((0, sub.generation));
            }
            anyhow::bail!("Subscription changed during access check");
        }
        let event: Value = serde_json::from_slice(&d.body)?;
        let access = self.policy.event_access_arguments(&event["data"])?;
        if !self.policy.authorize(sub.owner_id, &access).await? {
            return Ok((0, sub.generation));
        }
        let latest = db::get(&self.pool, &sub.id)
            .await?
            .context("Subscription unavailable")?;
        if latest.generation != sub.generation
            || latest.state != "active"
            || latest.expires_at <= Utc::now()
        {
            anyhow::bail!("Subscription changed before delivery")
        }
        let context = format!("{}/{}", sub.owner_id, sub.id);
        let secret = self.vault.open(&context, &sub.secret)?;
        let old = if sub.rotate_until.is_some_and(|t| t > Utc::now()) {
            sub.previous_secret
                .as_deref()
                .map(|s| self.vault.open(&context, s))
                .transpose()?
        } else {
            None
        };
        Ok((
            self.send(
                &sub,
                &d.event_id.to_string(),
                d.body.clone(),
                &secret,
                old.as_deref(),
            )
            .await?
            .status
            .as_u16(),
            sub.generation,
        ))
    }
}
pub fn subscription_ttl(params: &Value) -> anyhow::Result<i64> {
    match params.get("ttlMs") {
        None | Some(Value::Null) => Ok(86400000),
        Some(v) => {
            let ttl = v.as_i64().context("ttlMs must be a positive integer.")?;
            ensure!(ttl > 0, "ttlMs must be positive.");
            Ok(ttl.clamp(60000, 86400000))
        }
    }
}
fn subscription_identity(params: &Value) -> anyhow::Result<(&str, Value, &str)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .context("Choose an event name.")?;
    let args = params
        .get("arguments")
        .context("Provide event filters.")?
        .clone();
    ensure!(args.is_object(), "Event filters must be an object.");
    ensure!(
        params.pointer("/delivery/mode").and_then(Value::as_str) == Some("webhook"),
        "Webhook delivery is required."
    );
    let url = params
        .pointer("/delivery/url")
        .and_then(Value::as_str)
        .context("A callback URL is required.")?;
    Ok((name, args, url))
}
