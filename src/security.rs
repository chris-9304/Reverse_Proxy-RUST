use dashmap::DashMap;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use pingora::http::ResponseHeader;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const BLOCKED_USER_AGENTS: &[&str] = &["curl", "python-requests", "wget", "python-urllib"];
const BLOCKED_PATHS: &[&str] = &["/.env", "/.git", "/admin", "/.aws", "/.ssh"];
const PATH_TRAVERSAL: &str = "..";

pub struct SecurityLayer {
    rate_limit_store: DashMap<String, Mutex<SlidingWindow>>,
    rate_limit_per_second: u32,
    jwt_decoding_key: DecodingKey,
}

struct SlidingWindow {
    timestamps: Vec<Instant>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
}

impl SecurityLayer {
    pub fn new(rate_limit_per_second: u32, jwt_secret: &str) -> Self {
        Self {
            rate_limit_store: DashMap::new(),
            rate_limit_per_second,
            jwt_decoding_key: DecodingKey::from_secret(jwt_secret.as_bytes()),
        }
    }

    pub fn check_rate_limit(&self, client_ip: &str) -> Result<(), u16> {
        let now = Instant::now();
        let window_duration = Duration::from_secs(1);
        let limit = self.rate_limit_per_second as usize;

        let entry = self
            .rate_limit_store
            .entry(client_ip.to_string())
            .or_insert_with(|| {
                Mutex::new(SlidingWindow {
                    timestamps: Vec::new(),
                })
            });
        let mut guard = entry.lock().expect("lock");
        guard
            .timestamps
            .retain(|t| now.saturating_duration_since(*t) < window_duration);
        if guard.timestamps.len() >= limit {
            return Err(429);
        }
        guard.timestamps.push(now);
        Ok(())
    }

    pub fn check_user_agent(&self, user_agent: Option<&[u8]>) -> Result<(), u16> {
        let ua = match user_agent {
            Some(b) if !b.is_empty() => std::str::from_utf8(b).unwrap_or("").to_lowercase(),
            _ => return Err(403),
        };
        for blocked in BLOCKED_USER_AGENTS {
            if ua.contains(&blocked.to_lowercase()) {
                return Err(403);
            }
        }
        Ok(())
    }

    pub fn check_path(&self, path: &[u8]) -> Result<(), u16> {
        let path_str = std::str::from_utf8(path).unwrap_or("");
        if path_str.contains(PATH_TRAVERSAL) {
            return Err(403);
        }
        let path_lower = path_str.to_lowercase();
        for blocked in BLOCKED_PATHS {
            if path_lower.starts_with(blocked) {
                return Err(403);
            }
        }
        Ok(())
    }

    /// Check for valid JWT in Authorization header
    pub fn check_jwt(&self, auth_header: Option<&[u8]>) -> Result<(), u16> {
        let auth_val = match auth_header {
            Some(v) => std::str::from_utf8(v).unwrap_or(""),
            None => {
                println!("DEBUG JWT: Missing Authorization header");
                return Err(401);
            }
        };

        if !auth_val.starts_with("Bearer ") {
            println!("DEBUG JWT: Invalid format (missing 'Bearer ')");
            return Err(401);
        }

        let token = &auth_val[7..];
        // Force HS256 validation
        let validation = Validation::new(Algorithm::HS256);

        match decode::<Claims>(token, &self.jwt_decoding_key, &validation) {
            Ok(_) => Ok(()),
            Err(e) => {
                // THIS IS THE KEY: It will print why it failed
                println!("DEBUG JWT: Verification Failed! Reason: {:?}", e.kind());
                Err(401)
            }
        }
    }

    pub fn inject_security_headers(&self, resp: &mut ResponseHeader) {
        const HSTS: &str = "max-age=31536000; includeSubDomains; preload";
        let _ = resp.insert_header("Strict-Transport-Security", HSTS);
        let _ = resp.insert_header("X-Frame-Options", "DENY");
        let _ = resp.insert_header("X-Content-Type-Options", "nosniff");
        let _ = resp.insert_header("Content-Security-Policy", "default-src 'self'");
    }
}
