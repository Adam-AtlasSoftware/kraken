//! Platform transports: Unix domain socket or Windows named pipe.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Listener, Stream, connect};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{Listener, Stream, connect};

#[cfg(not(any(unix, windows)))]
compile_error!("kraken-ipc supports only unix and windows targets");
