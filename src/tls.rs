use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, info, warn};

/// Create a TLS server configuration from certificate and key files.
///
/// Uses TLS 1.3 only. Rejects TLS 1.0, 1.1, and 1.2.
pub fn create_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, String> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("Failed to set TLS certificate: {}", e))?;

    Ok(Arc::new(config))
}

/// Load certificates from a PEM file
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let cert_pem = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read certificate file '{}': {}", path, e))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .filter_map(|r| r.ok())
        .collect();

    if certs.is_empty() {
        return Err(format!("No certificates found in '{}'", path));
    }

    Ok(certs)
}

/// Load private key from a PEM file
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let key_pem = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read key file '{}': {}", path, e))?;

    match rustls_pemfile::private_key(&mut key_pem.as_bytes()) {
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err(format!("No private keys found in '{}'", path)),
        Err(e) => Err(format!("Failed to parse private key in '{}': {}", path, e)),
    }
}

/// Run an HTTPS server with TLS termination and graceful shutdown.
pub async fn serve_tls(
    app: Router,
    addr: std::net::SocketAddr,
    tls_config: Arc<ServerConfig>,
    shutdown_signal: impl Future<Output = ()>,
) {
    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind TLS listener");
    let tls_acceptor = TlsAcceptor::from(tls_config);

    let (close_tx, _) = watch::channel(false);

    info!(
        "TLS server listening on https://{}",
        listener.local_addr().unwrap()
    );

    let mut shutdown = std::pin::pin!(shutdown_signal);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Accept error: {}", e);
                        continue;
                    }
                };

                let tls_acceptor = tls_acceptor.clone();
                let router = app.clone();
                let mut close_rx = close_tx.subscribe();

                tokio::spawn(async move {
                    let tls_stream = match tokio::time::timeout(
                        Duration::from_secs(10),
                        tls_acceptor.accept(stream),
                    )
                    .await
                    {
                        Ok(Ok(s)) => TokioIo::new(s),
                        Ok(Err(e)) => {
                            warn!("TLS handshake failed from {}: {}", peer, e);
                            return;
                        }
                        Err(_) => {
                            warn!("TLS handshake timeout from {}", peer);
                            return;
                        }
                    };

                    let svc = service_fn(move |req: hyper::Request<Incoming>| {
                        let router = router.clone();
                        async move {
                            let (parts, incoming) = req.into_parts();
                            let body = axum::body::Body::new(incoming.map_err(axum::Error::new));
                            let req = axum::http::Request::from_parts(parts, body);
                            Ok::<_, std::convert::Infallible>(router.oneshot(req).await.unwrap())
                        }
                    });

                    let conn = http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(tls_stream, svc);

                    tokio::pin!(conn);

                    let mut shutdown_requested = false;

                    loop {
                        tokio::select! {
                            r = &mut conn => {
                                if let Err(e) = r {
                                    debug!("Connection from {}: {}", peer, e);
                                }
                                break;
                            }
                            _ = close_rx.changed(), if !shutdown_requested => {
                                shutdown_requested = true;
                                conn.as_mut().graceful_shutdown();
                            }
                        }
                    }
                });
            }
            _ = &mut shutdown => {
                info!("Shutdown signal received, stopping TLS server...");
                let _ = close_tx.send(true);
                tokio::time::sleep(Duration::from_secs(5)).await;
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn generate_test_cert_pem() -> (String, String) {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let key_pair = rcgen::KeyPair::generate_for(alg).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::NoCa;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    fn write_test_cert_files() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
        let (cert_pem, key_pem) = generate_test_cert_pem();
        let mut cert_file = tempfile::NamedTempFile::new().unwrap();
        cert_file.write_all(cert_pem.as_bytes()).unwrap();
        let mut key_file = tempfile::NamedTempFile::new().unwrap();
        key_file.write_all(key_pem.as_bytes()).unwrap();
        (cert_file, key_file)
    }

    #[test]
    fn test_load_certs_valid() {
        let (cert_file, _) = write_test_cert_files();
        let certs = load_certs(cert_file.path().to_str().unwrap());
        assert!(certs.is_ok());
        assert!(!certs.unwrap().is_empty());
    }

    #[test]
    fn test_load_certs_invalid_path() {
        let result = load_certs("/nonexistent/path/cert.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_key_valid() {
        let (_, key_file) = write_test_cert_files();
        let key = load_private_key(key_file.path().to_str().unwrap());
        assert!(key.is_ok());
    }

    #[test]
    fn test_load_key_invalid_path() {
        let result = load_private_key("/nonexistent/path/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_create_tls_config_valid() {
        let (cert_file, key_file) = write_test_cert_files();
        let config = create_tls_config(
            cert_file.path().to_str().unwrap(),
            key_file.path().to_str().unwrap(),
        );
        assert!(config.is_ok());

        // Config was built with TLS 1.3 only by builder_with_protocol_versions
        // ServerConfig doesn't expose a protocol_versions() query in rustls 0.23
        let _ = config.unwrap();
    }

    #[test]
    fn test_create_tls_config_invalid_cert() {
        let mut cert_file = tempfile::NamedTempFile::new().unwrap();
        cert_file.write_all(b"not a valid cert").unwrap();
        let mut key_file = tempfile::NamedTempFile::new().unwrap();
        key_file.write_all(b"not a valid key").unwrap();

        let config = create_tls_config(
            cert_file.path().to_str().unwrap(),
            key_file.path().to_str().unwrap(),
        );
        assert!(config.is_err());
    }

    #[test]
    fn test_load_certs_invalid_pem() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"invalid pem data").unwrap();
        let certs = load_certs(file.path().to_str().unwrap());
        assert!(certs.is_err());
    }

    #[test]
    fn test_load_key_invalid_pem() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"not a key").unwrap();
        let key = load_private_key(file.path().to_str().unwrap());
        assert!(key.is_err());
    }
}
