//! Shared local service infrastructure for NSE local protocol fixture tests.
//!
//! Provides lightweight TCP, HTTP, and UDP servers bound to `127.0.0.1` with
//! dynamic ports. Each server runs in a background thread/task and shuts down
//! when the returned handle is dropped.
//!
//! Run with:
//!   cargo test -p eggsec-nse --features nse --test local_protocol_tests

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ---------------------------------------------------------------------------
// TCP echo server
// ---------------------------------------------------------------------------

/// A lightweight TCP echo server bound to `127.0.0.1:<random>`.
///
/// Accepts connections, reads lines, echoes each line back prefixed with
/// `ECHO: `. Shuts down when the handle is dropped.
pub struct TcpEchoServer {
    port: u16,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TcpEchoServer {
    /// Start a TCP echo server on an ephemeral port.
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TCP echo server");
        let port = listener.local_addr().unwrap().port();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        // Non-blocking accept loop
        listener.set_nonblocking(true).unwrap();

        let handle = thread::spawn(move || {
            while !shutdown_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(3)))
                            .unwrap();
                        Self::handle_connection(stream);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            shutdown,
            handle: Some(handle),
        }
    }

    fn handle_connection(stream: TcpStream) {
        let reader = BufReader::new(stream.try_clone().unwrap());
        let mut writer = stream;
        for line in reader.lines().map_while(Result::ok) {
            let response = format!("ECHO: {}\n", line);
            if writer.write_all(response.as_bytes()).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    }

    /// The port this server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The address as `host:port` string.
    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

impl Drop for TcpEchoServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

/// A minimal HTTP/1.1 server bound to `127.0.0.1:<random>`.
///
/// Serves a fixed HTML page on GET `/` and handles POST `/api/test`.
/// Returns `404` for unknown paths.
pub struct HttpServer {
    port: u16,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    hits: Arc<AtomicUsize>,
    last_method: Arc<Mutex<Option<String>>>,
    last_path: Arc<Mutex<Option<String>>>,
}

impl HttpServer {
    /// Start an HTTP server on an ephemeral port.
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP server");
        let port = listener.local_addr().unwrap().port();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();
        let last_method = Arc::new(Mutex::new(None));
        let last_method_clone = last_method.clone();
        let last_path = Arc::new(Mutex::new(None));
        let last_path_clone = last_path.clone();

        listener.set_nonblocking(true).unwrap();

        let handle = thread::spawn(move || {
            while !shutdown_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        hits_clone.fetch_add(1, Ordering::Relaxed);
                        stream
                            .set_read_timeout(Some(Duration::from_secs(3)))
                            .unwrap();
                        Self::handle_connection(
                            stream,
                            last_method_clone.clone(),
                            last_path_clone.clone(),
                        );
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            shutdown,
            handle: Some(handle),
            hits,
            last_method,
            last_path,
        }
    }

    fn handle_connection(
        mut stream: TcpStream,
        last_method: Arc<Mutex<Option<String>>>,
        last_path: Arc<Mutex<Option<String>>>,
    ) {
        let reader = BufReader::new(stream.try_clone().unwrap());

        // Read request line + headers
        let mut request_line = String::new();
        let mut content_length: usize = 0;
        let mut headers_done = false;

        for line in reader.lines().map_while(Result::ok) {
            if request_line.is_empty() {
                request_line = line.clone();
            }
            if line.is_empty() {
                headers_done = true;
                break;
            }
            if line.to_lowercase().starts_with("content-length:") {
                if let Ok(len) = line[15..].trim().parse::<usize>() {
                    content_length = len;
                }
            }
        }

        if !headers_done {
            return;
        }

        // Read body if present
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            use std::io::Read;
            let _ = stream.read_exact(&mut body);
        }

        let method = request_line.split_whitespace().next().unwrap_or("GET");
        let path = request_line.split_whitespace().nth(1).unwrap_or("/");

        if let Ok(mut m) = last_method.lock() {
            *m = Some(method.to_string());
        }
        if let Ok(mut p) = last_path.lock() {
            *p = Some(path.to_string());
        }

        let (status, response_body) = match (method, path) {
            ("GET", "/") => (
                200,
                "<html><head><title>Eggsec Test Page</title></head><body><h1>Hello from Eggsec</h1></body></html>"
                    .to_string(),
            ),
            ("GET", "/headers") => {
                let headers_text = "Content-Type: text/html\r\nX-Custom: test-value\r\n";
                (200, headers_text.to_string())
            }
            ("POST", "/api/test") => {
                let body_str = String::from_utf8_lossy(&body);
                (200, format!("POST received: {}", body_str))
            }
            ("PUT", "/api/test") => {
                let body_str = String::from_utf8_lossy(&body);
                (200, format!("PUT received: {}", body_str))
            }
            ("DELETE", "/api/test") => (200, "DELETE received".to_string()),
            ("HEAD", "/") => (200, String::new()),
            ("OPTIONS", "/") => (200, String::new()),
            _ => (404, "Not Found".to_string()),
        };

        let response = if method == "HEAD" {
            format!(
                "HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                status,
                match status {
                    200 => "OK",
                    404 => "Not Found",
                    _ => "Unknown",
                },
            )
        } else {
            format!(
                "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                match status {
                    200 => "OK",
                    404 => "Not Found",
                    _ => "Unknown",
                },
                response_body.len(),
                response_body,
            )
        };

        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }

    /// The port this server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The base URL (e.g. `http://127.0.0.1:<port>`).
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// The number of connections accepted by this server.
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }

    /// The last HTTP method received by the server.
    pub fn last_method(&self) -> Option<String> {
        self.last_method.lock().ok().and_then(|m| m.clone())
    }

    /// The last HTTP path requested from the server.
    pub fn last_path(&self) -> Option<String> {
        self.last_path.lock().ok().and_then(|p| p.clone())
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ---------------------------------------------------------------------------
// UDP echo server
// ---------------------------------------------------------------------------

/// A lightweight UDP echo server bound to `127.0.0.1:<random>`.
///
/// Receives datagrams and echoes them back. Shuts down when dropped.
pub struct UdpEchoServer {
    port: u16,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl UdpEchoServer {
    /// Start a UDP echo server on an ephemeral port.
    pub fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP echo server");
        let port = socket.local_addr().unwrap().port();
        socket.set_nonblocking(true).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        let handle = thread::spawn(move || {
            let mut buf = [0u8; 65535];
            while !shutdown_clone.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        let _ = socket.send_to(&buf[..n], src);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            shutdown,
            handle: Some(handle),
        }
    }

    /// The port this server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for UdpEchoServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ---------------------------------------------------------------------------
// TLS echo server
// ---------------------------------------------------------------------------

/// A lightweight TLS echo server bound to `127.0.0.1:<random>`.
///
/// Generates a self-signed X.509 certificate at startup. Accepts TLS
/// connections, reads lines, echoes each line back prefixed with
/// `TLS_ECHO: `. Shuts down when the handle is dropped.
pub struct TlsEchoServer {
    port: u16,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    hits: Arc<AtomicUsize>,
    cert_subject: String,
    cert_der: Vec<u8>,
    cert_pem: String,
}

impl TlsEchoServer {
    /// Start a TLS echo server on an ephemeral port.
    pub fn start() -> Self {
        use native_tls::{Identity, TlsAcceptor};
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::X509Builder;
        use openssl::x509::X509NameBuilder;

        let rsa = Rsa::generate(2048).expect("generate RSA key");
        let pkey = PKey::from_rsa(rsa).expect("create PKey");

        let mut name_builder = X509NameBuilder::new().expect("create X509NameBuilder");
        name_builder
            .append_entry_by_text("CN", "localhost")
            .expect("set CN");
        let name = name_builder.build();

        let mut cert_builder = X509Builder::new().expect("create X509Builder");
        cert_builder.set_version(2).expect("set version");
        cert_builder.set_subject_name(&name).expect("set subject");
        cert_builder.set_issuer_name(&name).expect("set issuer");
        cert_builder.set_pubkey(&pkey).expect("set pubkey");

        let not_before = openssl::asn1::Asn1Time::days_from_now(0).expect("not_before");
        let not_after = openssl::asn1::Asn1Time::days_from_now(365).expect("not_after");
        cert_builder
            .set_not_before(&not_before)
            .expect("set not_before");
        cert_builder
            .set_not_after(&not_after)
            .expect("set not_after");

        cert_builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .expect("self-sign cert");
        let cert = cert_builder.build();

        let cert_der = cert.to_der().expect("cert to DER");
        let cert_pem =
            String::from_utf8(cert.to_pem().expect("cert to PEM")).expect("PEM is valid UTF-8");

        let pkcs12 = openssl::pkcs12::Pkcs12::builder()
            .pkey(&pkey)
            .cert(&cert)
            .build2("")
            .expect("build PKCS12");
        let pkcs12_der = pkcs12.to_der().expect("PKCS12 to DER");

        let identity = Identity::from_pkcs12(&pkcs12_der, "").expect("create Identity");
        let acceptor = TlsAcceptor::new(identity).expect("create TlsAcceptor");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS echo server");
        let port = listener.local_addr().unwrap().port();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();

        listener.set_nonblocking(true).unwrap();

        let handle = thread::spawn(move || {
            while !shutdown_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        hits_clone.fetch_add(1, Ordering::Relaxed);
                        stream
                            .set_read_timeout(Some(Duration::from_secs(3)))
                            .unwrap();
                        let acceptor = acceptor.clone();
                        thread::spawn(move || {
                            if let Ok(tls_stream) = acceptor.accept(stream) {
                                Self::handle_connection(tls_stream);
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            shutdown,
            handle: Some(handle),
            hits,
            cert_subject: "CN=localhost".to_string(),
            cert_der,
            cert_pem,
        }
    }

    fn handle_connection(mut stream: native_tls::TlsStream<TcpStream>) {
        use std::io::Read;
        let mut line_buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    if byte[0] == b'\n' {
                        let line = String::from_utf8_lossy(&line_buf).trim().to_string();
                        let response = format!("TLS_ECHO: {}\n", line);
                        if stream.write_all(response.as_bytes()).is_err() {
                            return;
                        }
                        let _ = stream.flush();
                        line_buf.clear();
                    } else {
                        line_buf.push(byte[0]);
                    }
                }
                Err(_) => break,
            }
        }
    }

    /// The port this server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The address as `host:port` string.
    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// The CN subject of the generated certificate.
    pub fn cert_subject(&self) -> String {
        self.cert_subject.clone()
    }

    /// The DER-encoded self-signed certificate.
    pub fn cert_der(&self) -> Vec<u8> {
        self.cert_der.clone()
    }

    /// The PEM-encoded self-signed certificate.
    pub fn cert_pem(&self) -> String {
        self.cert_pem.clone()
    }

    /// The number of connections accepted by this server.
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }
}

impl Drop for TlsEchoServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_echo_server_roundtrip() {
        let server = TcpEchoServer::start();
        let mut stream = TcpStream::connect(server.addr()).expect("connect to TCP echo server");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        writeln!(stream, "hello").unwrap();
        let mut buf = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut buf)
            .expect("read response");
        assert!(buf.contains("ECHO: hello"), "got: {}", buf);
    }

    #[test]
    fn udp_echo_server_roundtrip() {
        let server = UdpEchoServer::start();
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP client");
        socket
            .send_to(b"ping", format!("127.0.0.1:{}", server.port()))
            .expect("send");
        let mut buf = [0u8; 1024];
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let n = socket.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], b"ping");
    }

    #[test]
    fn http_server_roundtrip() {
        let server = HttpServer::start();
        let url = format!("{}/", server.base_url());
        let response = reqwest::blocking::get(&url).expect("GET /");
        assert_eq!(response.status(), 200);
        let body = response.text().unwrap();
        assert!(body.contains("Eggsec Test Page"), "body: {}", body);
    }

    #[test]
    fn tls_echo_server_roundtrip() {
        use native_tls::TlsConnector;
        use std::io::{BufRead, BufReader, Write};

        let server = TlsEchoServer::start();
        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .expect("build TLS connector");

        let tcp = TcpStream::connect(server.addr()).expect("connect to TLS server");
        tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut tls = connector.connect("localhost", tcp).expect("TLS handshake");

        tls.write_all(b"hello from tls\n").expect("write");
        tls.flush().expect("flush");

        let mut reader = BufReader::new(tls);
        let mut buf = String::new();
        reader.read_line(&mut buf).expect("read response");
        assert!(buf.contains("TLS_ECHO: hello from tls"), "got: {}", buf);
    }
}
