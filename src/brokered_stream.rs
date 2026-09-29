//! Brokered TCP stream compatibility adapter (M007B).
//!
//! Internal helper for migrating blocking-TCP protocol libraries off direct
//! `std::net::TcpStream` I/O without rewriting every protocol state machine.
//!
//! [`BrokeredTcpStream`] wraps an opaque [`NseTcpConnection`](crate::providers::NseTcpConnection)
//! obtained through [`broker_tcp_connect`](crate::providers::broker_tcp_connect) and exposes a
//! `TcpStream`-shaped surface (`connect`, `read`, `write`, `set_read_timeout`,
//! `set_write_timeout`) plus [`std::io::Read`] / [`std::io::Write`] impls so it can back
//! `native_tls::TlsConnector::connect` handshakes and internal `TcpStream`-plumbing helpers.
//!
//! Semantics (plan §4):
//!
//! - connect uses broker resolve-select-connect (DNS authority + capability + cancellation +
//!   accounting via `broker_tcp_connect`);
//! - writes go through [`broker_tcp_send`](crate::providers::broker_tcp_send) (write-bucket
//!   accounting, write limits, per-send capability + cancellation);
//! - reads go through [`broker_tcp_receive`](crate::providers::broker_tcp_receive) (read-bucket
//!   accounting, read limits);
//! - timeouts delegate to the provider handle (`set_timeouts`); `None` maps to a bounded
//!   120s default (documented behavior delta vs infinite blocking);
//! - cancellation/capability denial is preserved on every operation;
//! - errors map to [`std::io::Error`] with the broker denial text retained, so existing
//!   Lua/protocol failure mapping keeps working.
//!
//! The native socket is never exposed: there is no `into_inner`, `as_raw_fd`, `try_clone`,
//! `set_nonblocking`, or `shutdown` escape. Call sites needing those stay manual-only
//! (`NativeHandleEscape`).

use std::io::{self, Read, Write};
use std::time::Duration;

use crate::capabilities::NseCapabilityContext;
use crate::providers::{
    broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices, NseResolvedEndpoint,
    NseTcpConnection,
};
/// Default timeout applied when callers pass `None` (infinite) to
/// `set_read_timeout`/`set_write_timeout`.
///
/// The provider contract requires a concrete duration; infinite blocking has no
/// brokered equivalent. 120s keeps slow-protocol compatibility while staying bounded.
pub const BROKERED_STREAM_DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Opaque broker-backed TCP stream for migrated protocol libraries.
///
/// Construct via [`BrokeredTcpStream::connect`]; use through the inherent
/// `read`/`write`/timeout methods or the [`Read`]/[`Write`] trait impls.
pub struct BrokeredTcpStream {
    handle: Box<dyn NseTcpConnection>,
    ctx: NseCapabilityContext,
    operation: &'static str,
}

impl BrokeredTcpStream {
    /// Resolve, capability-check, and connect through the provider broker.
    ///
    /// `operation` labels capability/accounting entries (e.g. `"whois.whois"`).
    /// Returns the stream plus the approved concrete endpoint.
    pub fn connect(
        ctx: &NseCapabilityContext,
        services: &NseHostServices,
        host: &str,
        port: u16,
        timeout: Duration,
        operation: &'static str,
    ) -> Result<(Self, NseResolvedEndpoint), String> {
        let (handle, endpoint) = broker_tcp_connect(ctx, services, host, port, timeout, operation)?;
        Ok((
            Self {
                handle,
                ctx: ctx.clone(),
                operation,
            },
            endpoint,
        ))
    }

    /// Approved concrete endpoint backing this stream.
    pub fn endpoint(&self) -> &NseResolvedEndpoint {
        self.handle.endpoint()
    }

    /// Brokered read into `buf`; returns bytes read (0 on orderly EOF).
    ///
    /// Mirrors `TcpStream::read` so protocol loops keep working; every call is
    /// capability-checked, cancellation-checked, and read-bucket accounted.
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let data = broker_tcp_receive(&self.ctx, self.handle.as_mut(), buf.len(), self.operation)
            .map_err(io::Error::other)?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }

    /// Brokered write of the full `buf` (loops short writes like `write_all`).
    ///
    /// Mirrors the common `stream.write_all(...).ok()` protocol pattern while
    /// keeping every byte write-bucket accounted. Returns [`io::Error`] on the
    /// first denied/failed chunk.
    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let n = broker_tcp_send(
                &self.ctx,
                self.handle.as_mut(),
                &buf[written..],
                self.operation,
            )
            .map_err(io::Error::other)?;
            if n == 0 {
                return Err(io::Error::other("brokered TCP send wrote zero bytes"));
            }
            written += n;
        }
        Ok(written)
    }

    /// Delegate read timeout to the provider handle (`None` → bounded default).
    pub fn set_read_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        self.handle
            .set_timeouts(dur.unwrap_or(BROKERED_STREAM_DEFAULT_TIMEOUT))
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// Delegate write timeout to the provider handle (`None` → bounded default).
    pub fn set_write_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        self.handle
            .set_timeouts(dur.unwrap_or(BROKERED_STREAM_DEFAULT_TIMEOUT))
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// Non-destructive liveness probe (delegates to the provider handle).
    pub fn is_alive(&self) -> bool {
        self.handle.is_alive()
    }

    /// Close the handle (idempotent).
    pub fn close(&mut self) {
        self.handle.close();
    }
}

impl Read for BrokeredTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        BrokeredTcpStream::read(self, buf)
    }
}

impl Write for BrokeredTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        BrokeredTcpStream::write(self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Provider sends are unbuffered; nothing to flush.
        Ok(())
    }
}

/// Brokered `write_all` equivalent for migrated protocol libraries.
///
/// Loops [`broker_tcp_send`](crate::providers::broker_tcp_send) over short
/// writes so call sites keep their original all-or-error semantics with
/// every byte write-bucket accounted.
pub fn broker_send_all(
    ctx: &NseCapabilityContext,
    handle: &mut dyn NseTcpConnection,
    data: &[u8],
    operation: &'static str,
) -> Result<(), String> {
    let mut written = 0;
    while written < data.len() {
        let n = broker_tcp_send(ctx, handle, &data[written..], operation)?;
        if n == 0 {
            return Err("brokered TCP send wrote zero bytes".to_string());
        }
        written += n;
    }
    Ok(())
}

/// Drop-in brokered replacement for `TcpStream::write_all`.
///
/// Returns [`io::Result`] (broker denials surface as `ErrorKind::Other` with
/// the denial text retained) so migrated `stream.write_all(..).ok()`,
/// `.unwrap_or_else(..)`, `.map_err(..)?`, and `if ..is_err()` shapes keep
/// compiling unchanged.
pub fn broker_write_all(
    ctx: &NseCapabilityContext,
    handle: &mut dyn NseTcpConnection,
    data: &[u8],
    operation: &'static str,
) -> io::Result<()> {
    broker_send_all(ctx, handle, data, operation).map_err(io::Error::other)
}

/// Drop-in brokered replacement for `TcpStream::read`.
///
/// Reads up to `buf.len()` bytes through
/// [`broker_tcp_receive`](crate::providers::broker_tcp_receive) (read-bucket
/// accounted, capability- and cancellation-checked). Returns bytes read
/// (`0` on orderly EOF), matching `Read::read` semantics so protocol loops
/// keep working unchanged.
pub fn broker_read_into(
    ctx: &NseCapabilityContext,
    handle: &mut dyn NseTcpConnection,
    buf: &mut [u8],
    operation: &'static str,
) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let data = broker_tcp_receive(ctx, handle, buf.len(), operation).map_err(io::Error::other)?;
    let n = data.len().min(buf.len());
    buf[..n].copy_from_slice(&data[..n]);
    Ok(n)
}
