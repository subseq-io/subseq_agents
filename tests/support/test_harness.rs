use anyhow::{Result, anyhow};
use sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;

use subseq_agents::create_agent_tables;

const DEFAULT_POSTGRES_TEST_BASE_URL_PRIMARY: &str = "postgres://postgres@127.0.0.1:55432";
const DEFAULT_POSTGRES_TEST_BASE_URL_FALLBACK: &str = "postgres://postgres@127.0.0.1:5432";

pub struct TestDb {
    db_name: String,
    admin_url: String,
    pub pool: PgPool,
}

impl TestDb {
    pub async fn new() -> Result<Self> {
        let base_url = resolve_postgres_test_base_url().await?;
        let admin_url = format!("{base_url}/postgres");
        let db_name = format!("subseq_agents_test_{}", Uuid::new_v4().simple());

        let mut admin = PgConnection::connect(&admin_url).await?;
        let create_db = format!(r#"CREATE DATABASE "{}""#, db_name);
        sqlx::query(&create_db).execute(&mut admin).await?;

        let test_url = format!("{base_url}/{db_name}");
        let pool = PgPool::connect(&test_url).await?;

        Ok(Self {
            db_name,
            admin_url,
            pool,
        })
    }

    pub async fn prepare(&self) -> Result<()> {
        sqlx::query("CREATE SCHEMA IF NOT EXISTS auth")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS auth.users (
                id uuid PRIMARY KEY
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        create_agent_tables(&self.pool).await?;
        Ok(())
    }

    pub async fn teardown(self) -> Result<()> {
        self.pool.close().await;

        let mut admin = PgConnection::connect(&self.admin_url).await?;
        sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1")
            .bind(&self.db_name)
            .execute(&mut admin)
            .await?;
        let drop_db = format!(r#"DROP DATABASE IF EXISTS "{}""#, self.db_name);
        sqlx::query(&drop_db).execute(&mut admin).await?;
        Ok(())
    }
}

async fn resolve_postgres_test_base_url() -> Result<String> {
    let candidates = postgres_test_base_url_candidates();
    let mut failures = Vec::new();

    for candidate in candidates {
        let base_url = normalize_postgres_base_url(&candidate);
        let admin_url = format!("{base_url}/postgres");
        match PgConnection::connect(&admin_url).await {
            Ok(connection) => {
                connection.close().await?;
                return Ok(base_url);
            }
            Err(err) => failures.push(format!("{base_url}: {err}")),
        }
    }

    Err(anyhow!(
        "unable to connect to local postgres for tests. Set POSTGRES_TEST_BASE_URL. Attempted: {}",
        failures.join(" | ")
    ))
}

fn postgres_test_base_url_candidates() -> Vec<String> {
    if let Ok(base_url) = std::env::var("POSTGRES_TEST_BASE_URL") {
        let trimmed = base_url.trim();
        if !trimmed.is_empty() {
            return vec![trimmed.to_string()];
        }
    }

    vec![
        DEFAULT_POSTGRES_TEST_BASE_URL_PRIMARY.to_string(),
        DEFAULT_POSTGRES_TEST_BASE_URL_FALLBACK.to_string(),
    ]
}

fn normalize_postgres_base_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    trimmed
        .strip_suffix("/postgres")
        .unwrap_or(trimmed)
        .to_string()
}
