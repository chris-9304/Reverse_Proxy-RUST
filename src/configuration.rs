use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub listen_port: u16,
    pub upstream_ips: Vec<String>,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub rate_limit_per_second: u32,
    /// Secret key for validating JWT signatures (HS256)
    pub jwt_secret: String,
}

impl GatewayConfig {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(path.display().to_string(), e))?;
        serde_yaml::from_str(&contents).map_err(ConfigError::Parse)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.upstream_ips.is_empty() {
            return Err(ConfigError::Validation(
                "upstream_ips must not be empty".into(),
            ));
        }
        if self.rate_limit_per_second == 0 {
            return Err(ConfigError::Validation(
                "rate_limit_per_second must be greater than 0".into(),
            ));
        }
        if self.jwt_secret.is_empty() {
            return Err(ConfigError::Validation(
                "jwt_secret must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(String, std::io::Error),
    Parse(serde_yaml::Error),
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(path, e) => write!(f, "config io error at {}: {}", path, e),
            ConfigError::Parse(e) => write!(f, "config parse error: {}", e),
            ConfigError::Validation(s) => write!(f, "config validation: {}", s),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io(_, e) => Some(e),
            ConfigError::Parse(e) => Some(e),
            ConfigError::Validation(_) => None,
        }
    }
}
