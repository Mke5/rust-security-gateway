use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use once_cell::sync::Lazy;
use regex::Regex;
use tracing::debug;

/// SQL Injection patterns
static SQL_INJECTION_REGEX: Lazy<Vec<Regex>> = Lazy::new(|| {
    let patterns = vec![
        // Classic OR bypass: ' OR 1=1 -- or ' OR 'a'='a
        r"(?i)(\bor\b\s+\d+\s*=\s*\d+)",
        // Classic AND bypass: ' AND 1=1 --
        r"(?i)(\band\b\s+\d+\s*=\s*\d+)",
        // UNION-based injection: ' UNION SELECT * FROM users
        r"(?i)(union\s+(all\s+)?select)",
        // Comment sequences used to end SQL queries: -- or /*
        r"(?i)(-{2}|\\/\*|\*\\/)",
        // SELECT statement injection
        r"(?i)(select\s+.+\s+from\s+)",
        // INSERT/UPDATE/DELETE injection
        r"(?i)(insert\s+into|update\s+\w+\s+set|delete\s+from)",
        // DROP TABLE attack (most dangerous!)
        r"(?i)(drop\s+(table|database|index|view))",
        // Single quote followed by SQL keywords
        r"(?i)('\s*(or|and|union|select|insert|update|delete|drop|exec|execute))",
        // Hex encoding of SQL keywords (bypasses simple filters)
        r"(?i)(0x[0-9a-f]{2,})",
        // SQL function calls commonly used in attacks
        r"(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
        // EXEC/EXECUTE for stored procedures
        r"(?i)(\bexec\b|\bexecute\b)\s*[\(\s]",
        // INFORMATION_SCHEMA access (to read database structure)
        r"(?i)(information_schema|sys\.tables|all_tables)",
    ];

    patterns
        .into_iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
});

/// XSS (Cross-Site Scripting) patterns
static XSS_REGEX: Lazy<Vec<Regex>> = Lazy::new(|| {
    let patterns = vec![
        // Script tags: <script> or <SCRIPT>
        r"(?i)<\s*script[^>]*>",
        // Event handlers: onload=, onclick=, onerror=, etc.
        r"(?i)\bon\w+\s*=",
        // JavaScript protocol in links: javascript:alert(1)
        r"(?i)javascript\s*:",
        // Data URI with script: data:text/html,<script>
        r"(?i)data\s*:\s*text/html",
        // VBScript (older XSS technique): vbscript:
        r"(?i)vbscript\s*:",
        // Expression in CSS (IE XSS): expression(
        r"(?i)expression\s*\(",
        // eval() function call
        r"(?i)\beval\s*\(",
        // document.cookie access (stealing cookies)
        r"(?i)document\s*\.\s*cookie",
        // document.write for injection
        r"(?i)document\s*\.\s*write\s*\(",
        // innerHTML manipulation
        r"(?i)\.innerHTML\s*=",
        // SVG-based XSS
        r"(?i)<\s*svg[^>]*>",
        // Iframe injection
        r"(?i)<\s*iframe[^>]*>",
        // URL-encoded script tags: %3Cscript%3E
        r"(?i)%3c\s*script|%3cscript",
    ];

    patterns
        .into_iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
});

/// Path Traversal patterns
static PATH_TRAVERSAL_REGEX: Lazy<Vec<Regex>> = Lazy::new(|| {
    let patterns = vec![
        // Directory traversal: ../
        r"\.\./",
        // Windows style: ..\
        r"\.\.[/\\]",
        // URL encoded: %2e%2e%2f = ../
        r"(?i)%2e%2e[%/\\]",
        // Double-encoded: %252e%252e = ../
        r"(?i)%252e%252e",
        // Absolute paths to sensitive files
        r"(?i)/etc/passwd|/etc/shadow|/windows/win\.ini",
    ];

    patterns
        .into_iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
});

/// Command Injection patterns
static CMD_INJECTION_REGEX: Lazy<Vec<Regex>> = Lazy::new(|| {
    let patterns = vec![
        // Shell command separators: ; | & in suspicious contexts
        r"(?i);\s*(ls|cat|wget|curl|rm|mv|cp|chmod|chown|kill|ps)\b",
        // Pipe to commands
        r"\|\s*(bash|sh|cmd|powershell|python|perl|ruby|php)",
        // Backtick command execution
        r"`[^`]+`",
        // $() command substitution
        r"\$\([^)]+\)",
        // Common dangerous commands
        r"(?i)\b(wget|curl)\s+https?://",
        // Shell redirection to sensitive files
        r">\s*/etc/|>>\s*/etc/",
    ];

    patterns
        .into_iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
});

// =============================================================================
// WAF Rule Definition
// =============================================================================

/// Represents a single WAF rule with its category and description
struct WafRule {
    /// What type of attack this rule detects
    category: &'static str,
    /// Human-readable description
    description: &'static str,
    /// The compiled regex patterns for this rule
    patterns: &'static Lazy<Vec<Regex>>,
}

/// The Web Application Firewall
pub struct Waf {
    // The WAF uses global static regex patterns (defined above)
    // No mutable state needed - rules are compiled once at startup
}

impl Waf {
    pub fn new() -> Self {
        // Force initialization of all regex patterns at startup
        // This ensures we catch any invalid patterns early
        let sql_count = SQL_INJECTION_REGEX.len();
        let xss_count = XSS_REGEX.len();
        let path_count = PATH_TRAVERSAL_REGEX.len();
        let cmd_count = CMD_INJECTION_REGEX.len();

        debug!(
            "WAF initialized with {} SQL, {} XSS, {} Path Traversal, {} Command Injection rules",
            sql_count, xss_count, path_count, cmd_count
        );

        Waf {}
    }

    pub fn inspect_body(&self, body: &str) -> Result<(), Response> {
        if body.is_empty() {
            return Ok(());
        }

        debug!("WAF scanning body ({} chars)", body.len());

        self.scan(body, "body")
    }

    pub fn inspect_query(&self, query: &str) -> Result<(), Response> {
        if query.is_empty() {
            return Ok(());
        }

        debug!("WAF scanning query string ({} chars)", query.len());

        // URL-decode the query string first
        // Attackers might URL-encode their attacks: %27%20OR%201%3D1
        // URL-decoded: ' OR 1=1
        let decoded = url_decode(query);

        self.scan(&decoded, "query_string")
    }

    pub fn inspect_headers(&self, headers: &HeaderMap) -> Result<(), Response> {
        // Only scan headers that might contain user-controlled data
        // We skip headers like "Accept" that are browser-controlled
        let headers_to_scan = [
            "user-agent",
            "referer",
            "cookie",
            "x-forwarded-for",
            "x-custom-header",
            "authorization",
            "content-disposition",
        ];

        for header_name in &headers_to_scan {
            if let Some(value) = headers.get(*header_name) {
                if let Ok(value_str) = value.to_str() {
                    debug!("WAF scanning header: {}", header_name);
                    if let Err(e) = self.scan(value_str, &format!("header:{}", header_name)) {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    fn scan(&self, input: &str, source: &str) -> Result<(), Response> {
        // Define all our rule sets
        let rules: &[(&str, &str, &Lazy<Vec<Regex>>)] = &[
            ("SQL Injection", "sql_injection", &SQL_INJECTION_REGEX),
            ("XSS Attack", "xss", &XSS_REGEX),
            ("Path Traversal", "path_traversal", &PATH_TRAVERSAL_REGEX),
            ("Command Injection", "cmd_injection", &CMD_INJECTION_REGEX),
        ];

        for (attack_name, rule_id, patterns) in rules {
            for pattern in patterns.iter() {
                if pattern.is_match(input) {
                    // Found an attack pattern!
                    debug!(
                        "WAF ALERT: {} detected in {} | Pattern: {} | Input snippet: {}",
                        attack_name,
                        source,
                        pattern.as_str(),
                        // Only show first 100 chars to avoid logging huge payloads
                        &input[..input.len().min(100)]
                    );

                    return Err(waf_blocked_response(attack_name, rule_id, source));
                }
            }
        }

        Ok(())
    }
}

fn url_decode(input: &str) -> String {
    // Simple URL decoding for common encodings
    // In production, use the `percent-encoding` crate for full support
    input
        .replace("%27", "'")
        .replace("%22", "\"")
        .replace("%3C", "<")
        .replace("%3c", "<")
        .replace("%3E", ">")
        .replace("%3e", ">")
        .replace("%28", "(")
        .replace("%29", ")")
        .replace("%20", " ")
        .replace("%2F", "/")
        .replace("%2f", "/")
        .replace("%5C", "\\")
        .replace("%5c", "\\")
        .replace("+", " ") // + is space in URL encoding
}

fn waf_blocked_response(attack_name: &str, rule_id: &str, source: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        [
            ("Content-Type", "application/json"),
            ("X-Blocked-By", "RustGateway-WAF"),
            ("X-WAF-Rule", rule_id),
        ],
        format!(
            r#"{{
  "error": "Request Blocked by WAF",
  "attack_type": "{}",
  "rule_id": "{}",
  "source": "{}",
  "message": "Your request contains patterns associated with web attacks and has been blocked.",
  "code": 403
}}"#,
            attack_name, rule_id, source
        ),
    )
        .into_response()
}

impl Default for Waf {
    fn default() -> Self {
        Self::new()
    }
}
