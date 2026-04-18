use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tracing::debug;

/// The Bot Detector
pub struct BotDetector {
    block_missing_user_agent: bool,
    bad_user_agents: Vec<String>,
}

impl BotDetector {
    pub fn new(block_missing_user_agent: bool, bad_user_agents: Vec<String>) -> Self {
        // Convert all bad user agents to lowercase for case-insensitive matching
        // "SQLmap" and "sqlmap" and "SQLMAP" should all match
        let bad_user_agents = bad_user_agents
            .into_iter()
            .map(|ua| ua.to_lowercase())
            .collect();

        BotDetector {
            block_missing_user_agent,
            bad_user_agents,
        }
    }

    pub fn check(&self, headers: &HeaderMap) -> Result<(), Response> {
        // -----------------------------------------------------------------------
        // CHECK 1: Is the User-Agent header missing?
        // -----------------------------------------------------------------------
        let user_agent = headers.get("user-agent");

        if user_agent.is_none() {
            debug!("Bot detection: No User-Agent header found");

            if self.block_missing_user_agent {
                return Err(bot_blocked_response("missing_user_agent", "Access Denied."));
            }
        }

        // -----------------------------------------------------------------------
        // CHECK 2: Is the User-Agent in our bad list?
        // -----------------------------------------------------------------------
        if let Some(ua_header) = user_agent {
            // Convert the header to a string
            let ua_str = ua_header.to_str().unwrap_or("").to_lowercase(); // Make it lowercase for comparison

            debug!("Bot detection: Checking User-Agent: {}", ua_str);

            // Check if the User-Agent contains any bad strings
            for bad_ua in &self.bad_user_agents {
                if ua_str.contains(bad_ua.as_str()) {
                    debug!("Bot detection: Found bad User-Agent pattern: {}", bad_ua);
                    return Err(bot_blocked_response(
                        "bad_user_agent",
                        &format!("Access Denied: {}", bad_ua),
                    ));
                }
            }

            // -----------------------------------------------------------------------
            // CHECK 3: Is the User-Agent suspiciously short or fake-looking?
            // -----------------------------------------------------------------------
            // Very short User-Agents are suspicious (e.g., "bot", "test", "x")
            if ua_str.len() < 10 && !ua_str.is_empty() {
                debug!("Bot detection: Suspiciously short User-Agent: '{}'", ua_str);
                return Err(bot_blocked_response(
                    "suspicious_user_agent",
                    "Access Denied",
                ));
            }

            // -----------------------------------------------------------------------
            // CHECK 4: Does the User-Agent contain script injection?
            // -----------------------------------------------------------------------
            // Some bots try to inject code through the User-Agent header!
            let suspicious_patterns = ["<script", "javascript:", "eval(", "exec(", "system("];
            for pattern in &suspicious_patterns {
                if ua_str.contains(pattern) {
                    debug!("Bot detection: Script injection in User-Agent");
                    return Err(bot_blocked_response(
                        "injection_in_user_agent",
                        "Access Denied.",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn bot_blocked_response(reason: &str, message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        [
            ("Content-Type", "application/json"),
            ("X-Blocked-By", "RustGateway-BotDetector"),
            ("X-Block-Reason", reason),
        ],
        format!(
            r#"{{"error": "Bot Detected", "reason": "{}", "message": "{}"}}"#,
            reason, message
        ),
    )
        .into_response()
}
