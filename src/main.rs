use authentification::{Config, AppError, AppState, handlers};
use axum::{
    extract::State,
    http::{
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::json;
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
};
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "authentification=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env().map_err(|e| {
        eprintln!("Failed to load configuration: {}", e);
        e
    })?;

    info!("Starting {} in {} mode", config.app_name, config.app_env);

    // Initialize database connections
    let database = Database::new(&config.database_url, &config.redis_url).await?;
    info!("Database connections established");

    // Build our application with routes
    let app = create_app(config.clone(), database).await?;

    // Create socket address
    let addr = SocketAddr::from(([127, 0, 0, 1], config.server_port));
    info!("Server listening on {}", addr);

    // Start the server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn create_app(config: Config, database: authentification::database::Database) -> Result<Router, AppError> {
    // Setup CORS
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE])
        .allow_credentials(true)
        .allow_origin(
            config.cors_origins
                .iter()
                .map(|origin| origin.parse::<HeaderValue>().unwrap())
                .collect::<Vec<_>>(),
        );

    // Build the router with shared state
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        
        // Authentication routes
        .route("/api/auth/register", post(handlers::register_handler))
        .route("/api/auth/login", post(handlers::login_handler))
        .route("/api/auth/logout", post(handlers::logout_handler))
        .route("/api/auth/refresh", post(handlers::refresh_handler))
        .route("/api/auth/verify-email", post(handlers::verify_email_handler))
        .route("/api/auth/forgot-password", post(handlers::forgot_password_handler))
        .route("/api/auth/reset-password", post(handlers::reset_password_handler))
        
        .with_state(AppState { config, database })
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(cors),
        );

    Ok(app)
}

async fn health_check(State(state): State<AppState>) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.database.health_check().await {
        Ok(()) => Ok(Json(json!({
            "status": "ok",
            "message": "Auth microservice is running",
            "database": "connected",
            "redis": if state.database.redis().is_some() { "connected" } else { "fallback" },
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))),
        Err(e) => {
            error!("Health check failed: {}", e);
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Signal received, starting graceful shutdown");
}
