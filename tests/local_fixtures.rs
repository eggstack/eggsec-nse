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
use std::sync::Arc;
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

        listener.set_nonblocking(true).unwrap();

        let handle = thread::spawn(move || {
            while !shutdown_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        hits_clone.fetch_add(1, Ordering::Relaxed);
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
            hits,
        }
    }

    fn handle_connection(mut stream: TcpStream) {
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
            _ => (404, "Not Found".to_string()),
        };

        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status,
            match status {
                200 => "OK",
                404 => "Not Found",
                _ => "Unknown",
            },
            response_body.len(),
            response_body,
        );

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

// NOTE: TLS echo server deferred — the NSE socket library does raw TCP, not TLS.
// TLS testing requires the sslcert library's TlsConnector path, which is a
// separate test concern. See Milestone 5 Phase 03 plan.

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
}
