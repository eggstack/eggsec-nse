//! M007B: brokered TCP stream compatibility adapter tests.
//!
//! - loopback-style success through a memory provider (connect/read/write,
//!   endpoint identity, Read/Write trait impls, timeout delegation);
//! - denial/cancellation means zero provider contact;
//! - sends land in the write bucket, receives in the read bucket.

use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use eggsec_nse::brokered_stream::BrokeredTcpStream;
use eggsec_nse::{
    CountingTcpSocketProvider, NseCancellationToken, NseCapabilityContext, NseExecutionLimits,
    NseExecutionProfileKind, NseHostServices, NseResourceCounters, ResolvedNseExecutionProfile,
};

fn allow_loopback_ctx() -> (NseCapabilityContext, Arc<NseResourceCounters>) {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    let counters = Arc::new(NseResourceCounters::new());
    let ctx = NseCapabilityContext::new(
        NseExecutionProfileKind::ManualPermissive,
        profile.network_policy.clone(),
        profile.script_policy.clone(),
        profile.module_policy.clone(),
        profile.sandbox.clone(),
        NseExecutionLimits::default(),
        NseCancellationToken::new(),
        counters.clone(),
    );
    (ctx, counters)
}

fn deny_all_ctx() -> NseCapabilityContext {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    NseCapabilityContext::new(
        NseExecutionProfileKind::CiSafe,
        profile.network_policy.clone(),
        profile.script_policy.clone(),
        profile.module_policy.clone(),
        profile.sandbox.clone(),
        NseExecutionLimits::default(),
        NseCancellationToken::new(),
        Arc::new(NseResourceCounters::new()),
    )
}

fn memory_services(replay: Vec<Vec<u8>>) -> (NseHostServices, Arc<CountingTcpSocketProvider>) {
    let tcp = Arc::new(CountingTcpSocketProvider::new(replay));
    let services = NseHostServices::native().with_tcp(tcp.clone());
    (services, tcp)
}

#[test]
fn brokered_stream_connect_read_write_success() {
    let (ctx, _counters) = allow_loopback_ctx();
    let (services, tcp) = memory_services(vec![b"220 ready\r\n".to_vec()]);
    let timeout = Duration::from_secs(5);

    let (mut stream, endpoint) = BrokeredTcpStream::connect(
        &ctx,
        &services,
        "127.0.0.1",
        21,
        timeout,
        "test.brokered_stream",
    )
    .expect("brokered connect must succeed");
    assert_eq!(endpoint.port, 21);
    assert_eq!(tcp.calls(), 1, "exactly one provider connect");

    stream
        .write(b"HELP\r\n")
        .expect("brokered write must succeed");
    let mut buf = vec![0u8; 64];
    let n = stream.read(&mut buf).expect("brokered read must succeed");
    assert_eq!(&buf[..n], b"220 ready\r\n");
}

#[test]
fn brokered_stream_read_write_traits_work() {
    let (ctx, _counters) = allow_loopback_ctx();
    let (services, _tcp) = memory_services(vec![b"OK".to_vec()]);

    let (mut stream, _endpoint) = BrokeredTcpStream::connect(
        &ctx,
        &services,
        "127.0.0.1",
        80,
        Duration::from_secs(5),
        "test.brokered_stream_traits",
    )
    .expect("connect must succeed");

    // std::io::Write::write_all + flush route through the brokered impl.
    Write::write_all(&mut stream, b"ping").expect("write_all must succeed");
    Write::flush(&mut stream).expect("flush must succeed");

    // std::io::Read::read_exact routes through the brokered impl.
    let mut buf = [0u8; 2];
    Read::read_exact(&mut stream, &mut buf).expect("read_exact must succeed");
    assert_eq!(&buf, b"OK");
}

#[test]
fn brokered_stream_timeout_delegation() {
    let (ctx, _counters) = allow_loopback_ctx();
    let (services, _tcp) = memory_services(vec![]);

    let (mut stream, _endpoint) = BrokeredTcpStream::connect(
        &ctx,
        &services,
        "127.0.0.1",
        80,
        Duration::from_secs(5),
        "test.brokered_stream_timeouts",
    )
    .expect("connect must succeed");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout must delegate");
    stream
        .set_write_timeout(None)
        .expect("None timeout must map to bounded default");
    assert!(stream.is_alive());
    stream.close();
}

#[test]
fn brokered_stream_denied_means_zero_provider_contact() {
    let ctx = deny_all_ctx();
    let (services, tcp) = memory_services(vec![]);

    let err = match BrokeredTcpStream::connect(
        &ctx,
        &services,
        "127.0.0.1",
        21,
        Duration::from_secs(5),
        "test.brokered_stream_denied",
    ) {
        Ok(_) => panic!("DenyAll must refuse connect"),
        Err(e) => e,
    };
    assert!(
        err.contains("denied"),
        "denial text must be retained, got: {err}"
    );
    assert_eq!(tcp.calls(), 0, "denied connect must not touch provider");
}

#[test]
fn brokered_stream_cancelled_means_zero_provider_contact() {
    let (ctx, _counters) = allow_loopback_ctx();
    ctx.cancellation.cancel();
    let (services, tcp) = memory_services(vec![]);

    if BrokeredTcpStream::connect(
        &ctx,
        &services,
        "127.0.0.1",
        21,
        Duration::from_secs(5),
        "test.brokered_stream_cancelled",
    )
    .is_ok()
    {
        panic!("cancelled connect must fail");
    }
    assert_eq!(tcp.calls(), 0, "cancelled connect must not touch provider");
}

#[test]
fn brokered_stream_accounting_uses_correct_buckets() {
    let (ctx, counters) = allow_loopback_ctx();
    let (services, _tcp) = memory_services(vec![b"12345".to_vec()]);

    let (mut stream, _endpoint) = BrokeredTcpStream::connect(
        &ctx,
        &services,
        "127.0.0.1",
        80,
        Duration::from_secs(5),
        "test.brokered_stream_accounting",
    )
    .expect("connect must succeed");

    let payload = b"HELLO";
    stream.write(payload).expect("write must succeed");
    let mut buf = vec![0u8; 16];
    let n = stream.read(&mut buf).expect("read must succeed");
    assert_eq!(n, 5);

    assert_eq!(
        counters.network_bytes_written.load(Ordering::SeqCst),
        payload.len() as u64,
        "sends must land in the write bucket"
    );
    assert_eq!(
        counters.network_bytes_read.load(Ordering::SeqCst),
        5,
        "receives must land in the read bucket"
    );
}

#[test]
fn brokered_stream_send_denied_after_connect_is_surfaced() {
    // Connect allowed, then cancellation before write: write must fail
    // without provider contact beyond the initial connect.
    let (ctx, _counters) = allow_loopback_ctx();
    let (services, tcp) = memory_services(vec![]);

    let (mut stream, _endpoint) = BrokeredTcpStream::connect(
        &ctx,
        &services,
        "127.0.0.1",
        80,
        Duration::from_secs(5),
        "test.brokered_stream_send_cancel",
    )
    .expect("connect must succeed");
    let connects = tcp.calls();

    ctx.cancellation.cancel();
    let err = stream
        .write(b"data")
        .expect_err("cancelled write must fail");
    assert!(!err.to_string().is_empty());
    assert_eq!(
        tcp.calls(),
        connects,
        "cancelled write must not add provider contact"
    );
}
