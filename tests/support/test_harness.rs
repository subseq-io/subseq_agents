use anyhow::Result;
use sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;

use subseq_agents::create_agent_tables;

const POSTGRES_TEST_BASE_URL: &str = "postgres://postgres@localhost:5432";

pub struct TestDb {
    db_name: String,
    admin_url: String,
    pub pool: PgPool,
}

impl TestDb {
    pub async fn new() -> Result<Self> {
        let admin_url = format!("{POSTGRES_TEST_BASE_URL}/postgres");
        let db_name = format!("subseq_agents_test_{}", Uuid::new_v4().simple());

        let mut admin = PgConnection::connect(&admin_url).await?;
        let create_db = format!(r#"CREATE DATABASE "{}""#, db_name);
        sqlx::query(&create_db).execute(&mut admin).await?;

        let test_url = format!("{POSTGRES_TEST_BASE_URL}/{db_name}");
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
