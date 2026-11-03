use anyhow::{Context, ensure};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Clone, FromRow)]
pub struct Subscription {
    pub id: String,
    pub mount_name: String,
    pub owner_id: Uuid,
    pub api_key_id: Uuid,
    pub name: String,
    pub arguments: Value,
    pub callback_url: String,
    pub secret: String,
    pub secret_fingerprint: String,
    pub previous_secret: Option<String>,
    pub rotate_until: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub state: String,
    pub generation: i64,
    pub verify_until: Option<DateTime<Utc>>,
}
#[derive(FromRow)]
pub struct Delivery {
    pub subscription_id: String,
    pub event_id: Uuid,
    pub body: Vec<u8>,
    pub attempts: i32,
    pub lease_id: Option<Uuid>,
}

pub async fn principal_active(
    pool: &PgPool,
    owner: Uuid,
    key: Uuid,
    mount_name: &str,
) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agent.mcp_api_keys k JOIN auth.users u ON u.id=k.user_id WHERE k.id=$1 AND k.user_id=$2 AND k.mcp_mount_name=$3 AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>now()) AND u.active=true)").bind(key).bind(owner).bind(mount_name).fetch_one(pool).await?)
}
pub async fn user_active(pool: &PgPool, owner: Uuid) -> anyhow::Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth.users WHERE id=$1 AND active=true)")
            .bind(owner)
            .fetch_one(pool)
            .await?,
    )
}
pub async fn get(pool: &PgPool, id: &str) -> anyhow::Result<Option<Subscription>> {
    Ok(
        sqlx::query_as("SELECT * FROM mcp_event_subscriptions WHERE id=$1")
            .bind(id)
            .fetch_optional(pool)
            .await?,
    )
}
/// Serialize per-owner subscriptions/publications and reserve verification without holding a lock over HTTP.
pub async fn reserve(pool: &PgPool, sub: &Subscription) -> anyhow::Result<Subscription> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(sub.owner_id.to_string())
        .execute(&mut *tx)
        .await?;
    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mcp_event_subscriptions WHERE id=$1 AND verify_until>now())",
    )
    .bind(&sub.id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        !busy,
        "Subscription verification is in progress; please retry shortly."
    );
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mcp_event_subscriptions WHERE owner_id=$1 AND state IN ('active','verifying') AND expires_at>now() AND id<>$2 AND mount_name=$3").bind(sub.owner_id).bind(&sub.id).bind(&sub.mount_name).fetch_one(&mut *tx).await?;
    ensure!(
        count < 100,
        "Subscription limit reached. Stop an existing subscription first."
    );
    let result=sqlx::query_as::<_,Subscription>(r#"
        INSERT INTO mcp_event_subscriptions(id,owner_id,api_key_id,name,arguments,callback_url,secret,secret_fingerprint,expires_at,state,verify_until,pending_secret,pending_fingerprint,pending_expires_at,pending_api_key_id,mount_name)
        VALUES($1,$2,$3,$4,$5,$6,$7,$9,$8,'verifying',now()+interval '30 seconds',$7,$9,$8,$3,$10)
        ON CONFLICT(id) DO UPDATE SET
            pending_secret=EXCLUDED.secret, pending_fingerprint=EXCLUDED.secret_fingerprint,
            pending_expires_at=EXCLUDED.expires_at, pending_api_key_id=EXCLUDED.api_key_id,
            state=CASE WHEN mcp_event_subscriptions.state='active' AND mcp_event_subscriptions.expires_at>now() THEN 'active' ELSE 'verifying' END,
            verify_until=now()+interval '30 seconds', generation=mcp_event_subscriptions.generation+1,updated_at=now()
        RETURNING *"#)
        .bind(&sub.id).bind(sub.owner_id).bind(sub.api_key_id).bind(&sub.name).bind(&sub.arguments).bind(&sub.callback_url).bind(&sub.secret).bind(sub.expires_at).bind(&sub.secret_fingerprint).bind(&sub.mount_name).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(result)
}
pub async fn finish_verification(
    pool: &PgPool,
    id: &str,
    generation: i64,
    success: bool,
) -> anyhow::Result<bool> {
    if success {
        Ok(sqlx::query(r#"UPDATE mcp_event_subscriptions SET
            previous_secret=CASE WHEN state='active' THEN CASE WHEN secret_fingerprint<>pending_fingerprint THEN secret ELSE previous_secret END ELSE NULL END,
            rotate_until=CASE WHEN state='active' THEN CASE WHEN secret_fingerprint<>pending_fingerprint THEN now()+interval '5 minutes' ELSE rotate_until END ELSE NULL END,
            secret=pending_secret, secret_fingerprint=pending_fingerprint, expires_at=pending_expires_at,api_key_id=pending_api_key_id,
            state='active', generation=generation+1,verify_until=NULL,pending_secret=NULL,pending_fingerprint=NULL,pending_expires_at=NULL,pending_api_key_id=NULL,updated_at=now()
            WHERE id=$1 AND generation=$2 AND verify_until>now() AND pending_secret IS NOT NULL"#)
            .bind(id).bind(generation).execute(pool).await?.rows_affected()==1)
    } else {
        Ok(sqlx::query("UPDATE mcp_event_subscriptions SET state=CASE WHEN state='active' THEN 'active' ELSE 'failed' END,generation=generation+1,verify_until=NULL,pending_secret=NULL,pending_fingerprint=NULL,pending_expires_at=NULL,pending_api_key_id=NULL,updated_at=now() WHERE id=$1 AND generation=$2 AND verify_until>now()")
            .bind(id).bind(generation).execute(pool).await?.rows_affected()==1)
    }
}
/// A result from an old callback must never terminate a renewed or pending grant.
pub async fn stop_generation(pool: &PgPool, id: &str, generation: i64) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;
    let changed=sqlx::query("UPDATE mcp_event_subscriptions SET state='stopped',generation=generation+1,updated_at=now() WHERE id=$1 AND generation=$2 AND verify_until IS NULL").bind(id).bind(generation).execute(&mut *tx).await?.rows_affected()==1;
    if changed {
        sqlx::query("UPDATE mcp_event_deliveries SET state='cancelled',lease_id=NULL,lease_until=NULL WHERE subscription_id=$1 AND state IN ('pending','leased')").bind(id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(changed)
}

pub async fn stop(pool: &PgPool, id: &str, owner: Uuid) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE mcp_event_subscriptions SET state='stopped',generation=generation+1,updated_at=now(),verify_until=NULL,pending_secret=NULL,pending_fingerprint=NULL,pending_expires_at=NULL,pending_api_key_id=NULL WHERE id=$1 AND owner_id=$2").bind(id).bind(owner).execute(&mut *tx).await?;
    sqlx::query("UPDATE mcp_event_deliveries SET state='cancelled',lease_id=NULL,lease_until=NULL WHERE subscription_id=$1 AND state IN ('pending','leased') AND EXISTS(SELECT 1 FROM mcp_event_subscriptions WHERE id=$1 AND owner_id=$2)").bind(id).bind(owner).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
pub async fn publish(
    pool: &PgPool,
    mount_name: &str,
    producer: &str,
    producer_event: &str,
    owner: Uuid,
    name: &str,
    data: &Value,
    occurred: DateTime<Utc>,
) -> anyhow::Result<Uuid> {
    let occurred = DateTime::from_timestamp_micros(occurred.timestamp_micros())
        .context("Invalid event timestamp")?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(owner.to_string())
        .execute(&mut *tx)
        .await?;
    let id = Uuid::new_v4();
    let inserted=sqlx::query("INSERT INTO mcp_event_records(id,producer_id,producer_event_id,owner_id,name,data,occurred_at,mount_name) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(mount_name,producer_id,producer_event_id) DO NOTHING")
        .bind(id).bind(producer).bind(producer_event).bind(owner).bind(name).bind(data).bind(occurred).bind(mount_name).execute(&mut *tx).await?.rows_affected()==1;
    let existing:(Uuid,Uuid,String,Value,DateTime<Utc>)=sqlx::query_as("SELECT id,owner_id,name,data,occurred_at FROM mcp_event_records WHERE producer_id=$1 AND producer_event_id=$2 AND mount_name=$3").bind(producer).bind(producer_event).bind(mount_name).fetch_one(&mut *tx).await?;
    ensure!(
        existing.1 == owner && existing.2 == name && existing.3 == *data && existing.4 == occurred,
        "Event ID was already used with different content."
    );
    if inserted {
        let pending:i64=sqlx::query_scalar("SELECT count(*) FROM mcp_event_deliveries d JOIN mcp_event_subscriptions s ON s.id=d.subscription_id WHERE s.owner_id=$1 AND s.mount_name=$2 AND d.state IN ('pending','leased')").bind(owner).bind(mount_name).fetch_one(&mut *tx).await?;
        ensure!(pending < 10000, "Event queue is full. Please retry later.");
        let body = serde_json::to_vec(
            &serde_json::json!({"eventId":id,"name":name,"timestamp":occurred,"data":data,"cursor":null}),
        )?;
        ensure!(body.len() <= 262144, "Event is too large.");
        sqlx::query("INSERT INTO mcp_event_deliveries(subscription_id,event_id,body) SELECT id,$1,$2 FROM mcp_event_subscriptions WHERE owner_id=$3 AND name=$4 AND state IN ('active','verifying') AND expires_at>now() AND $5::jsonb @> arguments AND mount_name=$6 ON CONFLICT DO NOTHING")
            .bind(id).bind(body).bind(owner).bind(name).bind(data).bind(mount_name).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(existing.0)
}
pub async fn claim(pool: &PgPool, mount_name: &str) -> anyhow::Result<Option<Delivery>> {
    Ok(sqlx::query_as("WITH due AS (SELECT d.subscription_id,d.event_id FROM mcp_event_deliveries d JOIN mcp_event_subscriptions s ON s.id=d.subscription_id WHERE (d.state='pending' OR (d.state='leased' AND d.lease_until<now())) AND d.next_attempt<=now() AND s.state='active' AND s.expires_at>now() AND s.mount_name=$2 ORDER BY d.next_attempt FOR UPDATE OF d SKIP LOCKED LIMIT 1) UPDATE mcp_event_deliveries d SET state='leased',lease_id=$1,lease_until=now()+interval '60 seconds',attempts=d.attempts+1 FROM due WHERE d.subscription_id=due.subscription_id AND d.event_id=due.event_id RETURNING d.*")
        .bind(Uuid::new_v4()).bind(mount_name).fetch_optional(pool).await?)
}
pub async fn finish_delivery(
    pool: &PgPool,
    d: &Delivery,
    state: &str,
    status: Option<u16>,
    delay_seconds: i32,
) -> anyhow::Result<()> {
    ensure!(
        ["pending", "delivered", "dead", "cancelled"].contains(&state),
        "Invalid delivery state"
    );
    sqlx::query("UPDATE mcp_event_deliveries SET state=$4,last_status=$5,next_attempt=now()+make_interval(secs => $6::double precision),lease_id=NULL,lease_until=NULL WHERE subscription_id=$1 AND event_id=$2 AND lease_id=$3 AND state='leased'")
        .bind(&d.subscription_id).bind(d.event_id).bind(d.lease_id.context("Missing lease")?).bind(state).bind(status.map(i32::from)).bind(delay_seconds).execute(pool).await?;
    Ok(())
}
pub async fn sweep(pool: &PgPool, mount_name: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE mcp_event_subscriptions SET state=CASE WHEN state='verifying' THEN 'failed' ELSE state END,generation=generation+1,verify_until=NULL,pending_secret=NULL,pending_fingerprint=NULL,pending_expires_at=NULL,pending_api_key_id=NULL WHERE verify_until<=now() AND mount_name=$1").bind(mount_name).execute(pool).await?;
    sqlx::query("UPDATE mcp_event_deliveries d SET state='cancelled',lease_id=NULL,lease_until=NULL FROM mcp_event_subscriptions s WHERE s.mount_name=$1 AND d.subscription_id=s.id AND d.state IN ('pending','leased') AND ((s.expires_at<=now() AND s.verify_until IS NULL) OR s.state IN ('stopped','failed') OR (s.state='verifying' AND s.verify_until<=now()))").bind(mount_name).execute(pool).await?;
    sqlx::query("UPDATE mcp_event_subscriptions SET previous_secret=NULL,rotate_until=NULL WHERE rotate_until<=now() AND mount_name=$1").bind(mount_name).execute(pool).await?;
    Ok(())
}
