//! Windows named pipe transport (`\\.\pipe\kraken-<user>`).
//!
//! The first pipe instance is created with `first_pipe_instance(true)` so a squatter that created
//! the name earlier makes `bind` fail, and remote clients are rejected. Every instance carries an
//! explicit protected DACL that grants access only to the creating user's SID (not OWNER RIGHTS,
//! which matches every Administrators member when the daemon runs elevated), per decision 41; the auth token stays the second gate. This module is cross-compile
//! checked from Linux; it runs for real only in the Windows CI job.

use std::io;
use std::time::Duration;

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};

use crate::paths::RuntimeDir;

/// SDDL for the pipe: protected DACL (no inheritance), generic-all for exactly this user SID.
fn owner_only_sddl(user_sid: &str) -> String {
    format!("D:P(A;;GA;;;{user_sid})")
}

/// The string form (`S-1-5-21-...`) of the current process token's user SID.
fn current_user_sid_string() -> io::Result<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: plain FFI call with a valid out pointer; the token is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut needed = 0u32;
        // SAFETY: size query with a null buffer; fails with ERROR_INSUFFICIENT_BUFFER by design.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        // u64 elements keep the buffer aligned for TOKEN_USER.
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: `buf` is at least `needed` bytes.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the OS filled `buf` with a TOKEN_USER whose SID lives inside `buf`.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut wide = std::ptr::null_mut();
        // SAFETY: `sid` is valid; on success the OS allocates `wide`, freed with LocalFree.
        if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `wide` is a NUL-terminated UTF-16 string.
        let text = unsafe {
            let mut len = 0;
            while *wide.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(wide, len))
        };
        // SAFETY: allocated by ConvertSidToStringSidW.
        unsafe { LocalFree(wide.cast()) };
        Ok(text)
    })();
    // SAFETY: `token` was opened above.
    unsafe { CloseHandle(token) };
    result
}

/// A self-relative security descriptor allocated by the OS, freed on drop.
struct OwnerOnly {
    descriptor: *mut core::ffi::c_void,
}

// SAFETY: the descriptor is immutable after creation and only read by the pipe APIs.
unsafe impl Send for OwnerOnly {}
// SAFETY: see above.
unsafe impl Sync for OwnerOnly {}

impl OwnerOnly {
    fn new() -> io::Result<Self> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let sddl = owner_only_sddl(&current_user_sid_string()?);
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated; on success the OS allocates `descriptor`, which we
        // release with LocalFree in Drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnerOnly { descriptor })
    }

    /// Runs `create` with a `SECURITY_ATTRIBUTES` pointing at the descriptor.
    fn with_attributes<T>(
        &self,
        create: impl FnOnce(*mut core::ffi::c_void) -> io::Result<T>,
    ) -> io::Result<T> {
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor,
            bInheritHandle: 0,
        };
        create(std::ptr::addr_of_mut!(attrs).cast())
    }
}

impl Drop for OwnerOnly {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.descriptor);
        }
    }
}

fn create_instance(name: &str, first: bool, security: &OwnerOnly) -> io::Result<NamedPipeServer> {
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first).reject_remote_clients(true);
    // SAFETY: the attributes (and the descriptor they point at) outlive the call.
    security
        .with_attributes(|attrs| unsafe { opts.create_with_security_attributes_raw(name, attrs) })
}

/// A connected pipe, either end.
pub enum Stream {
    /// Server side.
    Server(NamedPipeServer),
    /// Client side.
    Client(NamedPipeClient),
}

macro_rules! delegate {
    ($self:ident, $s:ident => $e:expr) => {
        match $self.get_mut() {
            Stream::Server($s) => $e,
            Stream::Client($s) => $e,
        }
    };
}

impl tokio::io::AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        delegate!(self, s => std::pin::Pin::new(s).poll_read(cx, buf))
    }
}

impl tokio::io::AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        delegate!(self, s => std::pin::Pin::new(s).poll_write(cx, buf))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        delegate!(self, s => std::pin::Pin::new(s).poll_flush(cx))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        delegate!(self, s => std::pin::Pin::new(s).poll_shutdown(cx))
    }
}

/// Pipe listener.
pub struct Listener {
    name: String,
    security: OwnerOnly,
    next: Option<NamedPipeServer>,
}

impl Listener {
    /// Creates the first pipe instance.
    pub fn bind(dir: &RuntimeDir) -> io::Result<Self> {
        let name = dir.pipe_name();
        let security = OwnerOnly::new()?;
        let next = create_instance(&name, true, &security)?;
        Ok(Listener {
            name,
            security,
            next: Some(next),
        })
    }

    /// Waits for a client and prepares the next instance.
    pub async fn accept(&mut self) -> io::Result<Stream> {
        let server = match self.next.take() {
            Some(s) => s,
            None => create_instance(&self.name, false, &self.security)?,
        };
        server.connect().await?;
        self.next = Some(create_instance(&self.name, false, &self.security)?);
        Ok(Stream::Server(server))
    }
}

/// Opens the pipe, retrying briefly while all instances are busy.
pub async fn connect(dir: &RuntimeDir) -> io::Result<Stream> {
    const ERROR_PIPE_BUSY: i32 = 231;
    let name = dir.pipe_name();
    loop {
        match ClientOptions::new().open(&name) {
            Ok(c) => return Ok(Stream::Client(c)),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dacl_names_the_user_sid_not_owner_rights() {
        let sid = current_user_sid_string().unwrap();
        assert!(sid.starts_with("S-1-"), "{sid}");
        let sddl = owner_only_sddl(&sid);
        assert_eq!(sddl, format!("D:P(A;;GA;;;{sid})"));
        assert!(!sddl.contains(";OW)"));
        // The descriptor must also parse.
        OwnerOnly::new().unwrap();
    }
}
