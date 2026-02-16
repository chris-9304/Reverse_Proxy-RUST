mod configuration;
mod metrics;
mod proxy;
mod security;

use arc_swap::ArcSwap;
use configuration::GatewayConfig;
use metrics::Metrics;
use proxy::SecureProxy;
use security::SecurityLayer;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

use pingora::listeners::TlsSettings;
use pingora::prelude::*;

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

    tracing::info!("Starting FlashProxy with Hot Reload...");

    // --- HOT RELOAD SETUP ---
    let initial_security = SecurityLayer::new(config.rate_limit_per_second, &config.jwt_secret);
    let security_config = Arc::new(ArcSwap::from_pointee(initial_security));

    let security_reloader = security_config.clone();
    let config_path_reloader = config_path.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut sig_hup = signal(SignalKind::hangup()).unwrap();
            tracing::info!("Hot Reload Service active. Run 'kill -HUP <PID>' to reload.");

            loop {
                sig_hup.recv().await;
                tracing::info!("Received SIGHUP! Reloading configuration...");

                match GatewayConfig::from_file(&config_path_reloader) {
                    Ok(new_conf) => {
                        let new_layer = SecurityLayer::new(
                            new_conf.rate_limit_per_second,
                            &new_conf.jwt_secret,
                        );
                        security_reloader.store(Arc::new(new_layer));
                        tracing::info!("✅ Configuration successfully reloaded!");
                    }
                    Err(e) => {
                        tracing::error!("❌ Failed to reload config: {}. Keeping old config.", e);
                    }
                }
            }
        });
    });

    let upstream_list: Vec<&str> = config.upstream_ips.iter().map(String::as_str).collect();
    let mut lb = LoadBalancer::try_from_iter(upstream_list).expect("Invalid upstream list");

    let hc = TcpHealthCheck::new();
    lb.set_health_check(hc);
    lb.health_check_frequency = Some(std::time::Duration::from_secs(1));

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let background = background_service("health check", lb);
    let upstreams = background.task();

    // FIX IS HERE: We DO NOT wrap this in Arc::new().
    // Your Metrics::new() already returns Arc<Metrics>, so we assign it directly.
    let metrics = Metrics::new();

    let upstream_sni = config
        .upstream_ips
        .first()
        .and_then(|s| s.split(':').next())
        .unwrap_or("localhost")
        .to_string();

    let proxy = SecureProxy {
        lb: upstreams,
        security: security_config,
        // We pass the single-wrapped Arc here.
        metrics: metrics,
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
// upstream selection aint working idk why, need to fix it
