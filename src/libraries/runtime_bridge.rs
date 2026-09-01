//! Safe bridge for executing async work from synchronous Lua callbacks.
//!
//! Lua callbacks run synchronously on whatever thread invokes
//! `lua.call`. When invoked from a tokio task (e.g., via
//! `tokio::task::spawn_blocking` or directly from `eggsec::dispatch`),
//! `tokio::runtime::Handle::current().block_on` may panic with
//! "cannot execute blocking call inside blocking context".
//!
//! [`block_on_async`] handles both cases:
//! - If a tokio runtime is currently active, it delegates to the handle.
//! - Otherwise, it constructs an ephemeral current-thread runtime.
//!
//! This avoids the panic and removes the need for callers to manage
//! runtime lifecycle.

/// Run an async future to completion from a synchronous context.
///
/// Returns the future's output. If no tokio runtime is active in the
/// current thread, a dedicated current-thread runtime is constructed
/// and torn down on completion.
pub fn block_on_async<F>(fut: F) -> F::Output
where
    F: std::future::Future,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(fut),
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to construct dedicated runtime for NSE async bridge");
            rt.block_on(fut)
        }
    }
}
