// =============================================================================
// config/config.rs - Application Configuration
// =============================================================================
//
// WHAT IS THIS?
// This is like the settings panel on a TV remote.
// It reads our configuration file (config/default.toml) and turns those
// settings into Rust structs we can use in our code.
//
// Instead of hardcoding values like port 3000 in our code,
// we read them from a file. This makes it easy to change settings
// without rewriting code!
//
// =============================================================================

use serde::{Deserialize, Serialize};
use std::fs;

// =============================================================================
// The Main Config Struct
// =============================================================================
//
// #[derive(Debug, Deserialize, Serialize, Clone)] tells Rust to automatically
// generate code that lets us:
//   - Debug: Print this struct for debugging
//   - Deserialize: Read it FROM a TOML file
//   - Serialize: Write it TO a TOML file
//   - Clone: Make a copy of it
//
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppConfig {
    /// Settings for our gateway server (port, address)
    pub server: ServerConfig,

    /// Settings for the backend we forward to
    pub backend: BackendConfig,

    /// Rate limiting settings
    pub rate_limit: RateLimitConfig,

    /// Cache settings
    pub cache: CacheConfig,

    /// IP filtering settings
    pub ip_filter: IpFilterConfig,

    /// Bot detection settings
    pub bot_detection: BotDetectionConfig,

    /// WAF and body validation settings
    pub waf: WafConfig,
}

// =============================================================================
// Server Configuration
// =============================================================================
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    /// The hostname/IP to listen on
    /// "0.0.0.0" = listen on ALL network interfaces
    /// "127.0.0.1" = listen only on localhost
    pub host: String,

    /// The port to listen on (like a door number)
    pub port: u16,
}

// =============================================================================
// Backend Configuration
// =============================================================================
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BackendConfig {
    /// The full URL of the backend server
    /// Example: "http://localhost:8080" or "http://api.myapp.com"
    pub url: String,

    /// How many seconds to wait before giving up on a backend request
    pub timeout_seconds: u64,
}

// =============================================================================
// Rate Limit Configuration
// =============================================================================
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed per IP address
    pub max_requests: u64,

    /// The time window in seconds
    /// Example: 100 requests per 60 seconds = 100 requests per minute
    pub window_seconds: u64,
}

// =============================================================================
// Cache Configuration
// =============================================================================
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CacheConfig {
    /// How long to keep a cached response (in seconds)
    /// After this time, the cache entry expires and we fetch fresh data
    pub ttl_seconds: u64,

    /// Maximum number of responses to store in cache
    /// When we hit this limit, old entries are removed
    pub max_items: usize,
}

// =============================================================================
// IP Filter Configuration
// =============================================================================
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IpFilterConfig {
    /// IPs that are ALWAYS blocked
    /// Like a "banned forever" list
    pub blacklist: Vec<String>,

    /// IPs that are ALWAYS allowed (overrides everything else)
    /// If this list is NOT empty, ONLY these IPs can pass
    /// If this list IS empty, all IPs can pass (unless blacklisted)
    pub whitelist: Vec<String>,
}

// =============================================================================
// Bot Detection Configuration
// =============================================================================
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BotDetectionConfig {
    /// If true, block requests that have NO User-Agent header
    /// Real browsers always send a User-Agent
    pub block_missing_user_agent: bool,

    /// List of User-Agent strings that are known to be bad bots
    /// Example: "sqlmap" is a tool used to attack databases
    pub bad_user_agents: Vec<String>,
}

// =============================================================================
// WAF Configuration
// =============================================================================
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WafConfig {
    /// Maximum request body size in bytes
    /// 1,048,576 bytes = 1 MB
    /// If a request is larger than this, we reject it
    pub max_body_size: usize,
}

// =============================================================================
// Implementation - How to Load the Config
// =============================================================================
impl AppConfig {
    /// Load configuration from the config/default.toml file
    ///
    /// This function reads the file, parses the TOML, and returns an AppConfig.
    /// If anything goes wrong, it returns an error message.
    pub fn load() -> Result<Self, String> {
        // Try to read the config file
        // The path is relative to where you RUN the program from
        let config_content = fs::read_to_string("config/default.toml")
            .map_err(|e| format!("Cannot read config file 'config/default.toml': {}", e))?;

        // Parse the TOML text into our AppConfig struct
        toml::from_str(&config_content).map_err(|e| format!("Cannot parse config file: {}", e))
    }

    /// Load config with a custom path (useful for testing)
    pub fn load_from(path: &str) -> Result<Self, String> {
        let config_content = fs::read_to_string(path)
            .map_err(|e| format!("Cannot read config file '{}': {}", path, e))?;

        toml::from_str(&config_content).map_err(|e| format!("Cannot parse config file: {}", e))
    }

    /// Get the full listening address as a string
    /// Example: "0.0.0.0:3000"
    pub fn listen_addr(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }

    /// Validate all configuration values at startup.
    /// Returns a list of all validation errors found.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.server.host.is_empty() {
            errors.push("server.host must not be empty".to_string());
        }
        if self.server.port == 0 {
            errors.push("server.port must be non-zero".to_string());
        }

        if self.backend.url.is_empty() {
            errors.push("backend.url must not be empty".to_string());
        }
        if !self.backend.url.starts_with("http://") && !self.backend.url.starts_with("https://") {
            errors.push("backend.url must start with http:// or https://".to_string());
        }
        if self.backend.timeout_seconds == 0 {
            errors.push("backend.timeout_seconds must be > 0".to_string());
        }
        if self.rate_limit.max_requests == 0 {
            errors.push("rate_limit.max_requests must be > 0".to_string());
        }
        if self.rate_limit.window_seconds == 0 {
            errors.push("rate_limit.window_seconds must be > 0".to_string());
        }
        if self.cache.ttl_seconds == 0 {
            errors.push("cache.ttl_seconds must be > 0".to_string());
        }
        if self.cache.max_items == 0 {
            errors.push("cache.max_items must be > 0".to_string());
        }
        if self.waf.max_body_size == 0 {
            errors.push("waf.max_body_size must be > 0".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_load_valid() {
        let config = AppConfig::default();
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.backend.url, "http://localhost:8080");
        assert_eq!(config.rate_limit.max_requests, 100);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_port_zero() {
        let mut config = AppConfig::default();
        config.server.port = 0;
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("port")));
    }

    #[test]
    fn test_config_validate_empty_backend_url() {
        let mut config = AppConfig::default();
        config.backend.url = String::new();
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("backend.url")));
    }

    #[test]
    fn test_config_validate_invalid_backend_url() {
        let mut config = AppConfig::default();
        config.backend.url = "ftp://backend".to_string();
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("backend.url")));
    }

    #[test]
    fn test_config_validate_zero_timeout() {
        let mut config = AppConfig::default();
        config.backend.timeout_seconds = 0;
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("timeout")));
    }

    #[test]
    fn test_config_validate_zero_max_requests() {
        let mut config = AppConfig::default();
        config.rate_limit.max_requests = 0;
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("max_requests")));
    }

    #[test]
    fn test_config_validate_zero_window() {
        let mut config = AppConfig::default();
        config.rate_limit.window_seconds = 0;
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("window_seconds")));
    }

    #[test]
    fn test_config_validate_zero_ttl() {
        let mut config = AppConfig::default();
        config.cache.ttl_seconds = 0;
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("ttl_seconds")));
    }

    #[test]
    fn test_config_validate_zero_max_items() {
        let mut config = AppConfig::default();
        config.cache.max_items = 0;
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("max_items")));
    }

    #[test]
    fn test_config_validate_zero_body_size() {
        let mut config = AppConfig::default();
        config.waf.max_body_size = 0;
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("max_body_size")));
    }

    #[test]
    fn test_config_load_from_file() {
        // Write a temp config file
        let content = r#"
[server]
host = "127.0.0.1"
port = 9090

[backend]
url = "http://test:3000"
timeout_seconds = 15

[rate_limit]
max_requests = 50
window_seconds = 30

[cache]
ttl_seconds = 60
max_items = 500

[ip_filter]
blacklist = []
whitelist = []

[bot_detection]
block_missing_user_agent = false
bad_user_agents = ["test-bot"]

[waf]
max_body_size = 512000
"#;
        let path = "/tmp/test_config.toml";
        std::fs::write(path, content).unwrap();
        let config = AppConfig::load_from(path).unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 9090);
        assert_eq!(config.backend.url, "http://test:3000");
        assert_eq!(config.backend.timeout_seconds, 15);
        assert_eq!(config.rate_limit.max_requests, 50);
        assert_eq!(config.rate_limit.window_seconds, 30);
        assert_eq!(config.cache.ttl_seconds, 60);
        assert_eq!(config.cache.max_items, 500);
        assert_eq!(config.bot_detection.block_missing_user_agent, false);
        assert_eq!(config.waf.max_body_size, 512000);
        assert!(config.validate().is_ok());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_config_load_from_file_invalid() {
        let path = "/tmp/test_config_invalid.toml";
        std::fs::write(path, "invalid toml content {{{").unwrap();
        let result = AppConfig::load_from(path);
        assert!(result.is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_listen_addr() {
        let config = AppConfig::default();
        assert_eq!(config.listen_addr(), "0.0.0.0:3000");
    }

    #[test]
    fn test_multiple_validation_errors() {
        let mut config = AppConfig::default();
        config.server.port = 0;
        config.backend.timeout_seconds = 0;
        config.cache.max_items = 0;
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.len() >= 3);
    }
}

// =============================================================================
// Default Configuration
// =============================================================================
impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 3000,
            },
            backend: BackendConfig {
                url: "http://localhost:8080".to_string(),
                timeout_seconds: 30,
            },
            rate_limit: RateLimitConfig {
                max_requests: 100,
                window_seconds: 60,
            },
            cache: CacheConfig {
                ttl_seconds: 300,
                max_items: 1000,
            },
            ip_filter: IpFilterConfig {
                blacklist: vec![],
                whitelist: vec![],
            },
            bot_detection: BotDetectionConfig {
                block_missing_user_agent: true,
                bad_user_agents: vec!["sqlmap".to_string(), "nikto".to_string()],
            },
            waf: WafConfig {
                max_body_size: 1_048_576, // 1 MB
            },
        }
    }
}
