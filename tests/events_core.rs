use anyhow::ensure;
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use reqwest::{StatusCode, header::HeaderMap};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use subseq_agents::{
    ApiKeyStore, SqlxApiKeyStore,
    events::{
        EventPolicy, EventService, EventServiceConfig, Principal, PublishedEvent,
        crypto::{self, SecretBox},
        store,
        webhooks::{EventFuture, WebhookResponse, WebhookTransport},
    },
};
use subseq_auth::prelude::UserId;
use uuid::Uuid;
#[path = "support/test_harness.rs"]
mod test_harness;

struct QueuePolicy {
    owner: Uuid,
}
impl EventPolicy for QueuePolicy {
    fn catalog(&self) -> Vec<Value> {
        vec![json!({"name":"queue.changed","delivery":["webhook"]})]
    }
    fn validate_subscription(&self, name: &str, args: &Value) -> anyhow::Result<()> {
        ensure!(
            name == "queue.changed" && args.get("queue_id").and_then(Value::as_str).is_some(),
            "Invalid queue filter"
        );
        Ok(())
    }
    fn validate_event(&self, event: &PublishedEvent) -> anyhow::Result<()> {
        self.validate_subscription(&event.name, &event.data)
    }
    fn event_access_arguments(&self, data: &Value) -> anyhow::Result<Value> {
        Ok(json!({"queue_id":data["queue_id"]}))
    }
    fn authorize<'a>(&'a self, owner: Uuid, _args: &'a Value) -> EventFuture<'a, bool> {
        Box::pin(async move { Ok(owner == self.owner) })
    }
}
#[derive(Default)]
struct Receiver {
    deliveries: Mutex<Vec<Value>>,
}
impl WebhookTransport for Receiver {
    fn post<'a>(
        &'a self,
        _url: &'a str,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> EventFuture<'a, WebhookResponse> {
        Box::pin(async move {
            let value: Value = serde_json::from_slice(&body)?;
            let secret = format!("whsec_{}", STANDARD.encode([1u8; 32]));
            let id = headers["webhook-id"].to_str()?;
            let timestamp = headers["webhook-timestamp"].to_str()?.parse()?;
            ensure!(
                headers["webhook-signature"].to_str()?
                    == crypto::sign(&secret, id, timestamp, &body)?,
                "Invalid signature"
            );
            let response = if value.get("type") == Some(&json!("verification")) {
                json!({"challenge":value["challenge"]})
            } else {
                self.deliveries.lock().unwrap().push(value);
                json!({})
            };
            Ok(WebhookResponse {
                status: StatusCode::OK,
                body: serde_json::to_vec(&response)?,
            })
        })
    }
}
fn config(mount: &str) -> EventServiceConfig {
    EventServiceConfig {
        mount_name: mount.into(),
        encryption_key_id: "key".into(),
        encryption_keys: BTreeMap::from([("key".into(), STANDARD.encode([8u8; 32]))]),
    }
}
fn params() -> Value {
    json!({"name":"queue.changed","arguments":{"queue_id":"q1"},"delivery":{"mode":"webhook","url":"https://callback.example/queue","secret":format!("whsec_{}",STANDARD.encode([1u8;32]))}})
}
fn event(owner: Uuid, queue: &str) -> PublishedEvent {
    PublishedEvent {
        event_id: "producer-event-1".into(),
        user_id: owner,
        name: "queue.changed".into(),
        timestamp: Utc::now(),
        data: json!({"queue_id":queue,"state":"ready"}),
    }
}
#[tokio::test]
async fn reusable_policy_and_multiple_mounts_are_isolated() {
    let db = test_harness::TestDb::new().await.unwrap();
    db.prepare().await.unwrap();
    let owner = Uuid::new_v4();
    sqlx::query("INSERT INTO auth.users(id) VALUES($1)")
        .bind(owner)
        .execute(&db.pool)
        .await
        .unwrap();
    let keys = SqlxApiKeyStore::from_pool(&db.pool);
    let keya = keys
        .create_key(UserId(owner), "alpha", "test", None)
        .await
        .unwrap();
    let keyb = keys
        .create_key(UserId(owner), "beta", "test", None)
        .await
        .unwrap();
    let pa = Principal {
        owner,
        key: keya.metadata.id.0,
    };
    let pb = Principal {
        owner,
        key: keyb.metadata.id.0,
    };
    let policy = Arc::new(QueuePolicy { owner });
    let receiver = Arc::new(Receiver::default());
    let a = EventService::new(
        Arc::new(db.pool.clone()),
        config("alpha"),
        policy.clone(),
        receiver.clone(),
    )
    .unwrap();
    let b = EventService::new(
        Arc::new(db.pool.clone()),
        config("beta"),
        policy,
        receiver.clone(),
    )
    .unwrap();
    assert!(a.dispatch(pb, "events/subscribe", params()).await.is_err());
    let sa = a.dispatch(pa, "events/subscribe", params()).await.unwrap();
    let sb = b.dispatch(pb, "events/subscribe", params()).await.unwrap();
    assert_ne!(sa["id"], sb["id"]);
    let first = a.publish("producer", event(owner, "q1")).await.unwrap();
    let second = b.publish("producer", event(owner, "q1")).await.unwrap();
    assert_ne!(first, second);
    assert!(a.deliver_once().await.unwrap());
    assert!(!a.deliver_once().await.unwrap());
    assert!(b.deliver_once().await.unwrap());
    assert_eq!(receiver.deliveries.lock().unwrap().len(), 2);
    let mut unmatched = event(owner, "q2");
    unmatched.event_id = "unmatched".into();
    a.publish("producer", unmatched).await.unwrap();
    assert!(!a.deliver_once().await.unwrap());
    a.dispatch(pa, "events/unsubscribe", params())
        .await
        .unwrap();
    assert_eq!(
        store::get(&db.pool, sb["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .state,
        "active"
    );
    drop(a);
    drop(b);
    drop(keys);
    db.teardown().await.unwrap();
}
#[tokio::test]
async fn migration_preserves_legacy_router_identity_and_ciphertext() {
    let db = test_harness::TestDb::new().await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/20261103000000_mcp_events.sql"))
        .execute(&db.pool)
        .await
        .unwrap();
    let owner = Uuid::new_v4();
    let args = json!({"project_id":"p"});
    let id = crypto::identity(
        &owner.to_string(),
        "harness.message",
        "https://callback.example/legacy",
        &args,
    );
    let vault = SecretBox {
        current: "key".into(),
        keys: config("router").encryption_keys,
    };
    let context = format!("{owner}/{id}");
    let cipher = vault.seal(&context, "legacy-secret").unwrap();
    sqlx::query("INSERT INTO mcp_event_subscriptions(id,owner_id,api_key_id,name,arguments,callback_url,secret,secret_fingerprint,expires_at,state) VALUES($1,$2,$3,'harness.message',$4,'https://callback.example/legacy',$5,'fingerprint',now()+interval '1 day','active')").bind(&id).bind(owner).bind(Uuid::new_v4()).bind(args).bind(&cipher).execute(&db.pool).await.unwrap();
    db.prepare().await.unwrap();
    let row = store::get(&db.pool, &id).await.unwrap().unwrap();
    assert_eq!(row.mount_name, "router");
    assert_eq!(row.id, id);
    assert_eq!(row.secret, cipher);
    assert_eq!(vault.open(&context, &row.secret).unwrap(), "legacy-secret");
    db.teardown().await.unwrap();
}
