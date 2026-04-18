// =============================================================================
// middleware/ip_filter.rs - IP Blacklist/Whitelist Filter
// =============================================================================
//
// WHAT IS AN IP FILTER?
//
// An IP address is like your home address on the internet.
// Every device connected to the internet has one.
// Example: 192.168.1.1 or 216.58.209.46
//
// An IP filter is like a BOUNCER at a club who has two lists:
//
// BLACKLIST = "NEVER LET THESE PEOPLE IN"
//   These IPs are permanently banned (known hackers, spammers, etc.)
//
// WHITELIST = "ONLY LET THESE PEOPLE IN"
//   If the whitelist is set, ONLY these IPs are allowed.
//   Everyone else is blocked, no matter what.
//   (This is good for internal APIs that only certain servers should access)
//
// HOW THE CHECK WORKS:
//   1. Is the IP in the BLACKLIST? → BLOCK
//   2. Is there a WHITELIST and the IP is NOT in it? → BLOCK
//   3. Otherwise → ALLOW
//
// =============================================================================

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::collections::HashSet;
use tracing::debug;

/// The IP Filter - stores blacklisted and whitelisted IPs
pub struct IpFilter {
    /// IPs that are always blocked
    /// HashSet gives us super-fast O(1) lookup
    blacklist: HashSet<String>,

    /// IPs that are always allowed (if non-empty, others are blocked)
    whitelist: HashSet<String>,
}

impl IpFilter {
    pub fn new(blacklist: Vec<String>, whitelist: Vec<String>) -> Self {
        IpFilter {
            blacklist: blacklist.into_iter().collect(),
            whitelist: whitelist.into_iter().collect(),
        }
    }

    pub fn check(&self, ip: &str) -> Result<(), Response> {
        debug!("IP Filter checking: {}", ip);

        // -----------------------------------------------------------------------
        // CHECK 1: Is this IP in the blacklist?
        // -----------------------------------------------------------------------
        if self.blacklist.contains(ip) {
            debug!("IP {} is BLACKLISTED", ip);
            return Err(forbidden_response(&format!(
                "Your IP address ({}) has been blocked.",
                ip
            )));
        }

        // -----------------------------------------------------------------------
        // CHECK 2: Is there a whitelist, and is this IP NOT in it?
        // -----------------------------------------------------------------------
        // We only enforce the whitelist if it's not empty.
        // An empty whitelist means "no whitelist - allow everyone"
        if !self.whitelist.is_empty() && !self.whitelist.contains(ip) {
            debug!("IP {} is NOT in whitelist - blocking", ip);
            return Err(forbidden_response("Access denied."));
        }

        // -----------------------------------------------------------------------
        // ALLOWED ✅
        // -----------------------------------------------------------------------
        debug!("IP {} is ALLOWED", ip);
        Ok(())
    }

    pub fn blacklist_ip(&mut self, ip: String) {
        self.blacklist.insert(ip);
    }

    pub fn unblacklist_ip(&mut self, ip: &str) {
        self.blacklist.remove(ip);
    }

    pub fn is_blacklisted(&self, ip: &str) -> bool {
        self.blacklist.contains(ip)
    }

    pub fn blacklist_count(&self) -> usize {
        self.blacklist.len()
    }

    pub fn whitelist_count(&self) -> usize {
        self.whitelist.len()
    }
}

/// Create a "403 Forbidden" HTTP response with a message
fn forbidden_response(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        [
            ("Content-Type", "application/json"),
            ("X-Blocked-By", "RustGateway-IPFilter"),
        ],
        format!(
            r#"{{"error": "Forbidden", "message": "{}", "code": 403}}"#,
            message
        ),
    )
        .into_response()
}
