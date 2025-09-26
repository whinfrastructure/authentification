use redis::aio::ConnectionManager;
use sqlx::{migrate::MigrateDatabase, sqlite::SqlitePoolOptions, SqlitePool};
use std::time::Duration;
use tracing::{info, warn};

#[derive(Clone)]
pub struct Database {
    pub sqlite_pool: SqlitePool,
    pub redis_manager: Option<ConnectionManager>,
}

impl Database {
    pub async fn new(database_url: &str, redis_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Create SQLite database if it doesn't exist
        if !sqlx::Sqlite::database_exists(database_url).await.unwrap_or(false) {
            info!("Creating database {}", database_url);
            sqlx::Sqlite::create_database(database_url).await?;
        }

        // Create connection pool
        let sqlite_pool = SqlitePoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await?;

        // Run migrations
        info!("Running database migrations");
        sqlx::migrate!("./migrations").run(&sqlite_pool).await?;

        // Try to connect to Redis (optional, fallback to SQLite for rate limiting)
        let redis_manager = match redis::Client::open(redis_url) {
            Ok(client) => match ConnectionManager::new(client).await {
                Ok(manager) => {
                    info!("Connected to Redis");
                    Some(manager)
                }
                Err(e) => {
                    warn!("Failed to connect to Redis: {}. Using SQLite fallback", e);
                    None
                }
            },
            Err(e) => {
                warn!("Failed to create Redis client: {}. Using SQLite fallback", e);
                None
            }
        };

        Ok(Database {
            sqlite_pool,
            redis_manager,
        })
    }

    pub fn sqlite(&self) -> &SqlitePool {
        &self.sqlite_pool
    }

    pub fn redis(&self) -> Option<&ConnectionManager> {
        self.redis_manager.as_ref()
    }

    pub async fn health_check(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Check SQLite
        sqlx::query("SELECT 1").execute(&self.sqlite_pool).await?;
        
        // Check Redis if available
        if let Some(redis) = &self.redis_manager {
            let mut conn = redis.clone();
            redis::cmd("PING").query_async::<_, String>(&mut conn).await?;
        }

        Ok(())
    }
}
