mod configuration;
mod metrics;
mod proxy;
mod security;

use configuration::GatewayConfig;
use metrics::Metrics;
use proxy::SecureProxy;
use security::SecurityLayer;
use std::sync::Arc;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

use pingora::listeners::TlsSettings;
use pingora::prelude::*;
// Added imports for token generation
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::Serialize;

#[derive(Serialize)]
struct SetupClaims {
    sub: String,
    exp: usize,
}

fn main() {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.yaml".to_string());

    let config = match GatewayConfig::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config from {}: {}", config_path, e);
            std::process::exit(1);
        }
    };
    if let Err(e) = config.validate() {
        eprintln!("Invalid config: {}", e);
        std::process::exit(1);
    }

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_span_events(FmtSpan::NONE)
                .with_current_span(false)
                .with_target(false),
        )
        .init();

    tracing::info!("Starting Secure Gateway...");

    // Ticket generator
    let my_claims = SetupClaims {
        sub: "admin".to_owned(),
        exp: 10000000000, // Valid for a long time
    };
    let key = config.jwt_secret.trim(); // Ensure we use the trimmed key
    let token = encode(
        &Header::default(),
        &my_claims,
        &EncodingKey::from_secret(key.as_bytes()),
    )
    .unwrap();

    let upstream_list: Vec<&str> = config.upstream_ips.iter().map(String::as_str).collect();
    let mut lb = LoadBalancer::try_from_iter(upstream_list).expect("Invalid upstream list");

    let hc = TcpHealthCheck::new();
    lb.set_health_check(hc);
    lb.health_check_frequency = Some(std::time::Duration::from_secs(1));

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let background = background_service("health check", lb);
    let upstreams = background.task();

    let security = Arc::new(SecurityLayer::new(config.rate_limit_per_second, key));
    let metrics = Metrics::new();

    let upstream_sni = config
        .upstream_ips
        .first()
        .and_then(|s| s.split(':').next())
        .unwrap_or("localhost")
        .to_string();

    let proxy = SecureProxy {
        lb: upstreams,
        security,
        metrics,
        upstream_sni,
    };

    let mut proxy_service = http_proxy_service(&server.configuration, proxy);

    let mut tls_settings =
        TlsSettings::intermediate(&config.tls_cert_path, &config.tls_key_path).unwrap();
    tls_settings.enable_h2();

    let listen_addr = format!("0.0.0.0:{}", config.listen_port);
    tracing::info!(addr = %listen_addr, "Listening for HTTPS");
    proxy_service.add_tls_with_settings(&listen_addr, None, tls_settings);

    server.add_service(proxy_service);
    server.add_service(background);
    server.run_forever();
}

// upstream aint working idk why, need to fix it
