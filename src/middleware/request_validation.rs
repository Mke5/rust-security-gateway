use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use tracing::debug;

pub struct RequestValidator {
    /// Maximum allowed body size in bytes
    max_body_size: usize,
}

impl RequestValidator {
    pub fn new(max_body_size: usize) -> Self {
        RequestValidator { max_body_size }
    }

    pub fn check_body_size(&self, body: &Bytes) -> Result<(), Response> {
        let size = body.len();
        debug!(
            "Request body size: {} bytes (limit: {})",
            size, self.max_body_size
        );

        if size > self.max_body_size {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE, // HTTP 413
                [
                    ("Content-Type", "application/json"),
                    ("X-Blocked-By", "RustGateway-Validator"),
                ],
                format!(
                    r#"{{"error": "Maximum allowed is {} bytes."}}"#,
                    self.max_body_size
                ),
            )
                .into_response());
        }

        Ok(())
    }

    pub fn validate_headers(&self, headers: &HeaderMap) -> Result<(), Response> {
        // Check: are there too many headers?
        // A normal request has maybe 10-20 headers
        // 100+ headers is very suspicious
        const MAX_HEADERS: usize = 100;
        if headers.len() > MAX_HEADERS {
            debug!("Too many headers: {}", headers.len());
            return Err(bad_request_response(
                "too_many_headers",
                &format!(
                    "Request has {} headers. Maximum allowed is {}.",
                    headers.len(),
                    MAX_HEADERS
                ),
            ));
        }

        // Check each header
        for (name, value) in headers.iter() {
            // Check: is the header value too long?
            // Normal headers are under 1000 characters
            // Very long headers might be trying to overflow buffers
            const MAX_HEADER_VALUE_SIZE: usize = 8192; // 8 KB
            if value.len() > MAX_HEADER_VALUE_SIZE {
                debug!("Oversized header: {} ({} bytes)", name, value.len());
                return Err(bad_request_response(
                    "oversized_header",
                    &format!(
                        "Header '{}' is too large ({} bytes). Maximum is {} bytes.",
                        name,
                        value.len(),
                        MAX_HEADER_VALUE_SIZE
                    ),
                ));
            }

            // Check: does the header value contain null bytes?
            // Null bytes (0x00) in headers can cause parsing bugs
            if value.as_bytes().contains(&0u8) {
                debug!("Null byte in header: {}", name);
                return Err(bad_request_response(
                    "null_byte_in_header",
                    &format!("Header '{}' contains invalid null byte.", name),
                ));
            }
        }

        Ok(())
    }

    pub fn validate_content_type(
        &self,
        method: &axum::http::Method,
        headers: &HeaderMap,
        body_size: usize,
    ) -> Result<(), Response> {
        use axum::http::Method;

        // Only check Content-Type for requests that have a body
        let has_body = matches!(method, &Method::POST | &Method::PUT | &Method::PATCH);

        if has_body && body_size > 0 {
            if headers.get("content-type").is_none() {
                debug!("Missing Content-Type for {} request with body", method);
                // Note: we warn but don't block - some APIs work without Content-Type
                // In strict mode, you'd return an error here
            }
        }

        Ok(())
    }
}

fn bad_request_response(reason: &str, message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST, // HTTP 400
        [
            ("Content-Type", "application/json"),
            ("X-Blocked-By", "RustGateway-Validator"),
        ],
        format!(
            r#"{{"error": "Bad Request", "reason": "{}", "message": "{}"}}"#,
            reason, message
        ),
    )
        .into_response()
}
