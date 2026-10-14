use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    /// Inbound HTTP listen address for the WAF reverse proxy.
    pub listen_addr: String,

    /// Upstream target application URL (e.g. http://127.0.0.1:3000).
    pub upstream_url: String,

    /// Operation mode: "block" (default) or "monitor" (dry-run).
    #[serde(default = "default_mode")]
    pub mode: String,

    /// EXACTOR Core Cloud API URL (defaults to https://exactor.tech/api/simplify).
    #[serde(default = "default_exactor_api_url")]
    pub exactor_api_url: String,

    /// EXACTOR Cloud API Token or Bearer Token.
    pub exactor_api_token: Option<String>,

    /// Local SQLite WAL Ledger database file path.
    #[serde(default = "default_database_path")]
    pub database_path: String,

    /// Autonomous background sync interval in seconds.
    #[serde(default = "default_sync_interval")]
    pub autonomous_sync_interval_secs: u64,

    /// Enable automatic hot minimization sync with https://exactor.tech.
    #[serde(default = "default_auto_sync")]
    pub auto_sync_enabled: bool,

    /// Enable stateful behavioral inspection (sliding windows).
    #[serde(default = "default_stateful_enabled")]
    pub stateful_enabled: bool,

    /// Max requests allowed in sliding window per IP across all endpoints.
    #[serde(default = "default_global_limit")]
    pub stateful_global_limit: u32,

    /// Max requests allowed in sliding window per IP on auth/login endpoints.
    #[serde(default = "default_auth_limit")]
    pub stateful_auth_limit: u32,

    /// Sliding window duration in seconds.
    #[serde(default = "default_window_secs")]
    pub stateful_window_secs: u64,

    /// Quarantine / ban duration in seconds for offenders.
    #[serde(default = "default_ban_secs")]
    pub stateful_ban_secs: u64,

    /// Optional Redis connection URL (e.g. redis://127.0.0.1:6379).
    pub redis_url: Option<String>,
}

fn default_mode() -> String {
    "block".to_string()
}

fn default_exactor_api_url() -> String {
    "https://exactor.tech/api/simplify".to_string()
}

fn default_database_path() -> String {
    "waf_ledger.db".to_string()
}

fn default_sync_interval() -> u64 {
    300
}

fn default_auto_sync() -> bool {
    true
}

fn default_stateful_enabled() -> bool {
    true
}

fn default_global_limit() -> u32 {
    300
}

fn default_auth_limit() -> u32 {
    20
}

fn default_window_secs() -> u64 {
    60
}

fn default_ban_secs() -> u64 {
    180
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".to_string(),
            upstream_url: "http://127.0.0.1:3000".to_string(),
            mode: default_mode(),
            exactor_api_url: default_exactor_api_url(),
            exactor_api_token: None,
            database_path: default_database_path(),
            autonomous_sync_interval_secs: default_sync_interval(),
            auto_sync_enabled: default_auto_sync(),
            stateful_enabled: default_stateful_enabled(),
            stateful_global_limit: default_global_limit(),
            stateful_auth_limit: default_auth_limit(),
            stateful_window_secs: default_window_secs(),
            stateful_ban_secs: default_ban_secs(),
            redis_url: None,
        }
    }
}

impl WafConfig {
    /// Loads configuration from file if exists, falling back to environment variables and defaults.
    pub fn load_or_default(path_opt: Option<&str>) -> Self {
        let mut cfg = if let Some(path) = path_opt {
            if Path::new(path).exists() {
                match std::fs::read_to_string(path) {
                    Ok(content) => match toml::from_str::<WafConfig>(&content) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("Warning: Failed to parse {}: {}. Using defaults.", path, e);
                            WafConfig::default()
                        }
                    },
                    Err(e) => {
                        eprintln!("Warning: Failed to read {}: {}. Using defaults.", path, e);
                        WafConfig::default()
                    }
                }
            } else {
                WafConfig::default()
            }
        } else if Path::new("waf_config.toml").exists() {
            match std::fs::read_to_string("waf_config.toml") {
                Ok(content) => toml::from_str(&content).unwrap_or_default(),
                Err(_) => WafConfig::default(),
            }
        } else {
            WafConfig::default()
        };

        // Override with environment variables if present
        if let Ok(v) = std::env::var("WAF_LISTEN_ADDR") {
            cfg.listen_addr = v;
        }
        if let Ok(v) = std::env::var("WAF_UPSTREAM_URL") {
            cfg.upstream_url = v;
        }
        if let Ok(v) = std::env::var("WAF_MODE") {
            cfg.mode = v;
        }
        if let Ok(v) = std::env::var("EXACTOR_API_URL") {
            cfg.exactor_api_url = v;
        }
        if let Ok(v) = std::env::var("EXACTOR_API_TOKEN") {
            cfg.exactor_api_token = Some(v);
        }
        if let Ok(v) = std::env::var("WAF_DATABASE_PATH") {
            cfg.database_path = v;
        }

        cfg
    }

    /// Converts WafConfig parameters into a StatefulConfig for the sliding window engine.
    pub fn to_stateful_config(&self) -> crate::stateful::StatefulConfig {
        crate::stateful::StatefulConfig {
            enabled: self.stateful_enabled,
            window_secs: self.stateful_window_secs,
            num_buckets: 12,
            global_limit_per_window: self.stateful_global_limit,
            auth_limit_per_window: self.stateful_auth_limit,
            ban_duration_secs: self.stateful_ban_secs,
            redis_url: self.redis_url.clone(),
        }
    }
}

