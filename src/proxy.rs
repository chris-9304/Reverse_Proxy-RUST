use crate::metrics::Metrics;
use crate::security::SecurityLayer;
use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader; // <--- ADDED IMPORT
use pingora::prelude::*;
use std::sync::Arc;
use std::time::Instant;
use tracing;

pub struct RequestCtx {
    pub start: Instant,
    pub method: String,
    pub path: String,
}

pub struct SecureProxy {
    pub lb: Arc<LoadBalancer<RoundRobin>>,
    pub security: Arc<SecurityLayer>,
    pub metrics: Arc<Metrics>,
    pub upstream_sni: String,
}

#[async_trait]
impl ProxyHttp for SecureProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            start: Instant::now(),
            method: String::new(),
            path: String::new(),
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.req_header();
        let path_bytes = req.raw_path();
        let path = std::str::from_utf8(path_bytes).unwrap_or("").to_string();
        let method = req.method.as_str().to_string();

        ctx.path = path.clone();
        ctx.method = method.clone();

        // 1. Intercept /metrics endpoint
        if path == "/metrics" && method == "GET" {
            let body = self
                .metrics
                .encode()
                .map_err(|e| {
                    pingora::Error::explain(
                        pingora::ErrorType::InternalError,
                        format!("metrics encode: {}", e),
                    )
                })?
                .into_bytes();
            let mut header = ResponseHeader::build(200, Some(4)).map_err(|e| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!("response header build: {}", e),
                )
            })?;
            header.insert_header("Content-Type", "text/plain").map_err(|e| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!("insert header: {}", e),
                )
            })?;

            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(Bytes::from(body)), true)
                .await?;

            return Ok(true); // Stop processing, request handled
        }

        // 2. Security Checks
        let user_agent = session.get_header("User-Agent").map(|v| v.as_bytes());
        let auth_header = session.get_header("Authorization").map(|v| v.as_bytes());
        let client_ip = session
            .client_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        if let Err(code) = self.security.check_rate_limit(&client_ip) {
            tracing::warn!(client_ip = %client_ip, "rate limit exceeded");
            session.respond_error(code).await?;
            return Ok(true);
        }

        if let Err(code) = self.security.check_path(path_bytes) {
            tracing::warn!(path = %path, "blocked path");
            session.respond_error(code).await?;
            return Ok(true);
        }

        if let Err(code) = self.security.check_user_agent(user_agent) {
            tracing::warn!(client_ip = %client_ip, "blocked user agent");
            session.respond_error(code).await?;
            return Ok(true);
        }

        // 3. JWT Authentication (The Bouncer)
        if let Err(code) = self.security.check_jwt(auth_header) {
            tracing::warn!(client_ip = %client_ip, "jwt auth failed");
            session.respond_error(code).await?;
            return Ok(true);
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let upstream = self.lb.select(b"", 256).ok_or_else(|| {
            pingora::Error::explain(pingora::ErrorType::InternalError, "no healthy upstream")
        })?;

        let peer = Box::new(HttpPeer::new(upstream, true, self.upstream_sni.clone()));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request
            .insert_header("Host", self.upstream_sni.as_str())
            .map_err(|e| {
                pingora::Error::explain(pingora::ErrorType::InternalError, e.to_string())
            })?;
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        self.security.inject_security_headers(upstream_response);
        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let duration = ctx.start.elapsed().as_secs_f64();
        let client_ip = session
            .client_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let status_code = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        // Record metrics
        self.metrics
            .record_request(status_code, &ctx.method, &ctx.path, duration);

        tracing::info!(
            client_ip = %client_ip,
            method = %ctx.method,
            path = %ctx.path,
            latency_sec = %duration,
            status_code = %status_code,
            "request"
        );
    }
}
