//! OS-level peer credentials and platform security primitives.
//!
//! This crate is the *only* unsafe FFI boundary in the host workspace (the
//! workspace lint `unsafe_code = "forbid"` is deliberately not inherited
//! here — see Cargo.toml). `std` still marks `UnixStream::peer_cred`
//! unstable, and Windows Named Pipe client token / SID queries
//! require platform FFI.
//!
//! Platform features provided:
//! - Unix peer UID (`getpeereid` on macOS/BSD, `getsockopt(SO_PEERCRED)` on Linux)
//! - Windows peer SID (kernel-supplied pipe client PID -> process token SID)
//! - [`Principal`] unified identity representation (UnixUid / WindowsSid)
//! - [`fill_random`] OS CSPRNG (`/dev/urandom` on Unix, `BCryptGenRandom` on Windows)
//! - Private file and directory permission checks (Unix 0600/0700, Windows ACLs)

use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;

/// Authenticated local process identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Principal {
    UnixUid(u32),
    WindowsSid(String),
}

impl From<u32> for Principal {
    fn from(uid: u32) -> Self {
        Self::UnixUid(uid)
    }
}

impl Principal {
    /// Versioned, lossless key for durable ownership and idempotency records.
    /// The prefix keeps a Unix UID distinct from a Windows SID in every store.
    pub fn storage_key(&self) -> String {
        match self {
            Principal::UnixUid(uid) => format!("v1:uid:{uid}"),
            Principal::WindowsSid(sid) => format!("v1:sid:{sid}"),
        }
    }

    pub fn from_storage_key(key: &str) -> Result<Self, String> {
        let value = key
            .strip_prefix("v1:")
            .ok_or_else(|| "unknown principal storage version".to_string())?;
        let principal: Principal = value.parse()?;
        if principal.storage_key() != key {
            return Err("noncanonical principal storage key".into());
        }
        Ok(principal)
    }

    pub fn as_unix_uid(&self) -> Option<u32> {
        match self {
            Principal::UnixUid(uid) => Some(*uid),
            _ => None,
        }
    }

    pub fn as_windows_sid(&self) -> Option<&str> {
        match self {
            Principal::WindowsSid(sid) => Some(sid.as_str()),
            _ => None,
        }
    }
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Principal::UnixUid(uid) => write!(f, "{uid}"),
            Principal::WindowsSid(sid) => write!(f, "{sid}"),
        }
    }
}

impl std::str::FromStr for Principal {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if let Some(uid_str) = trimmed.strip_prefix("uid:") {
            let uid = uid_str
                .parse::<u32>()
                .map_err(|e| format!("invalid uid '{uid_str}': {e}"))?;
            return Ok(Principal::UnixUid(uid));
        }
        if let Some(sid_str) = trimmed.strip_prefix("sid:") {
            if sid_str.starts_with("S-") {
                return Ok(Principal::WindowsSid(sid_str.to_string()));
            }
            return Err(format!("invalid SID format: {sid_str}"));
        }
        if let Ok(uid) = trimmed.parse::<u32>() {
            return Ok(Principal::UnixUid(uid));
        }
        if trimmed.starts_with("S-") {
            return Ok(Principal::WindowsSid(trimmed.to_string()));
        }
        Err(format!("invalid principal format: '{s}'"))
    }
}

/// Returns the effective uid of the process on the other end of `stream`.
#[cfg(unix)]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    imp::peer_uid(stream)
}

/// Returns the authenticated local [`Principal`] of the peer on `stream`.
#[cfg(unix)]
pub fn peer_principal(stream: &UnixStream) -> io::Result<Principal> {
    peer_uid(stream).map(Principal::UnixUid)
}

/// Fills `out` with cryptographically secure random bytes from the OS CSPRNG.
/// Never downgrades to time/pid material on failure.
pub fn fill_random(out: &mut [u8]) -> io::Result<()> {
    if out.is_empty() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut file = std::fs::File::open("/dev/urandom")?;
        file.read_exact(out)
    }
    #[cfg(windows)]
    {
        win_rand::fill_random(out)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "OS CSPRNG not supported on this platform",
        ))
    }
}

/// Verifies that `path` is a regular file with owner-only access permissions
/// (Unix 0600 or Windows owner-only DACL).
pub fn verify_private_file_perms(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file is not a regular file",
            ));
        }
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file is group/other-accessible (chmod 0600 required)",
            ));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file is not a regular file",
            ));
        }
        win_acl::verify_owner_only(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "permissions check not supported on this platform",
        ))
    }
}

/// Protects a SQLite sidecar created under a verified private directory.
/// SQLite creates WAL/journal files itself, so their inherited ACL must be
/// made explicit before the daemon serves requests.
#[cfg(windows)]
pub fn protect_private_sidecar(path: &Path) -> io::Result<()> {
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sidecar is not a regular file",
        ));
    }
    win_acl::protect_owner_only(path)
}

/// Verifies that `path` is a directory with owner-only access permissions
/// (Unix 0700 or Windows owner-only DACL).
pub fn verify_private_dir_perms(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path is not a directory",
            ));
        }
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory is group/other-accessible (chmod 0700 required)",
            ));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path is not a directory",
            ));
        }
        win_acl::verify_owner_only(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "permissions check not supported on this platform",
        ))
    }
}

/// Creates a directory and parents with owner-only access permissions (Unix 0700).
pub fn create_private_dir_all(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(windows)]
    {
        win_acl::create_private_dir_all(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Atomically opens/creates a private file for writing with owner-only permissions (Unix 0600).
pub fn open_private_file_for_write(path: &Path) -> io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(windows)]
    {
        win_acl::open_private_file_for_write(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
    }
}

/// Opens the bridge serial port with exclusive access and raw 8N1 settings.
pub fn open_serial(path: &Path) -> io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        win_serial::open(path)
    }
    #[cfg(not(windows))]
    {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
    }
}

/// Distinguishes a COM read timeout from a disconnected adapter.
#[cfg(windows)]
pub fn serial_idle_check(file: &std::fs::File) -> io::Result<()> {
    win_serial::idle_check(file)
}

/// Publishes a staged directory without replacing a concurrent publisher.
pub fn publish_dir_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        extern "C" {
            fn renamex_np(from: *const i8, to: *const i8, flags: u32) -> i32;
        }
        let source = std::ffi::CString::new(from.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
        let target = std::ffi::CString::new(to.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
        // RENAME_EXCL makes publication atomic even if another process races.
        if unsafe { renamex_np(source.as_ptr(), target.as_ptr(), 0x4) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(windows)]
    {
        win_acl::publish_dir_noreplace(from, to)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (from, to);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "publish requires platform rename",
        ))
    }
}

/// Non-blocking exclusive file lock (Unix flock or Windows LockFileEx).
/// Returns Ok(true) if the lock was acquired, Ok(false) if the file is currently locked
/// by another process.
pub fn try_lock_file_exclusive(file: &std::fs::File) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        const LOCK_EX: i32 = 2;
        const LOCK_NB: i32 = 4;
        let fd = file.as_raw_fd();
        let res = unsafe { flock(fd, LOCK_EX | LOCK_NB) };
        if res == 0 {
            Ok(true)
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(11) || err.raw_os_error() == Some(35) {
                Ok(false)
            } else {
                Err(err)
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let handle = file.as_raw_handle();
        #[repr(C)]
        struct Overlapped {
            internal: usize,
            internal_high: usize,
            offset: u32,
            offset_high: u32,
            h_event: *mut std::ffi::c_void,
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn LockFileEx(
                hFile: *mut std::ffi::c_void,
                dwFlags: u32,
                dwReserved: u32,
                nNumberOfBytesToLockLow: u32,
                nNumberOfBytesToLockHigh: u32,
                lpOverlapped: *mut Overlapped,
            ) -> i32;
        }
        const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x00000002;
        const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x00000001;

        let mut ov: Overlapped = unsafe { std::mem::zeroed() };
        let res = unsafe {
            LockFileEx(
                handle as *mut _,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut ov,
            )
        };
        if res != 0 {
            Ok(true)
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(33) {
                Ok(false)
            } else {
                Err(err)
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Ok(true)
    }
}

/// Unlocks a file previously locked with try_lock_file_exclusive.
pub fn unlock_file(file: &std::fs::File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        const LOCK_UN: i32 = 8;
        let fd = file.as_raw_fd();
        let res = unsafe { flock(fd, LOCK_UN) };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let handle = file.as_raw_handle();
        #[link(name = "kernel32")]
        extern "system" {
            fn UnlockFile(
                hFile: *mut std::ffi::c_void,
                dwFileOffsetLow: u32,
                dwFileOffsetHigh: u32,
                nNumberOfBytesToUnlockLow: u32,
                nNumberOfBytesToUnlockHigh: u32,
            ) -> i32;
        }
        let res = unsafe { UnlockFile(handle as *mut _, 0, 0, 1, 0) };
        if res != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Ok(())
    }
}

pub mod ipc {
    #[cfg(unix)]
    use super::peer_principal;
    use super::Principal;
    use std::io::{self, Read, Write};
    use std::path::Path;
    use std::time::Duration;

    #[cfg(unix)]
    use std::os::unix::net::{UnixListener, UnixStream};

    /// Cross-platform local IPC stream (Unix domain socket or Windows Named Pipe).
    #[derive(Debug)]
    pub struct IpcStream {
        #[cfg(unix)]
        pub(crate) inner: UnixStream,
        #[cfg(windows)]
        pub(crate) inner: std::sync::Arc<super::win_ipc::PipeStream>,
    }

    impl IpcStream {
        #[cfg(unix)]
        pub fn from_unix(stream: UnixStream) -> Self {
            Self { inner: stream }
        }

        #[cfg(unix)]
        pub fn as_unix(&self) -> &UnixStream {
            &self.inner
        }

        #[cfg(windows)]
        fn from_file(file: std::fs::File) -> io::Result<Self> {
            Ok(Self {
                inner: std::sync::Arc::new(super::win_ipc::PipeStream::new(file)?),
            })
        }

        #[cfg(unix)]
        pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self> {
            let stream = UnixStream::connect(path)?;
            Ok(Self { inner: stream })
        }

        #[cfg(windows)]
        pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self> {
            let path_str = path.as_ref().to_string_lossy();
            let file = super::win_ipc::connect_pipe(&path_str)?;
            Self::from_file(file)
        }

        #[cfg(not(any(unix, windows)))]
        pub fn connect<P: AsRef<Path>>(_path: P) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported platform",
            ))
        }

        #[cfg(unix)]
        pub fn pair() -> io::Result<(Self, Self)> {
            let (a, b) = UnixStream::pair()?;
            Ok((Self { inner: a }, Self { inner: b }))
        }

        #[cfg(windows)]
        pub fn pair() -> io::Result<(Self, Self)> {
            use std::sync::atomic::{AtomicU64, Ordering};
            static PAIR_ID: AtomicU64 = AtomicU64::new(0);
            let id = PAIR_ID.fetch_add(1, Ordering::Relaxed);
            let name = format!(r"\\.\pipe\routeloom-pair-{}-{}", std::process::id(), id);
            let listener = super::win_ipc::NamedPipeListener::bind(&name)?;
            let client = super::win_ipc::connect_pipe(&name)?;
            let (server, _) = listener.accept()?;
            Ok((Self::from_file(client)?, Self::from_file(server)?))
        }

        #[cfg(not(any(unix, windows)))]
        pub fn pair() -> io::Result<(Self, Self)> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported platform",
            ))
        }

        pub fn try_clone(&self) -> io::Result<Self> {
            #[cfg(unix)]
            {
                self.inner.try_clone().map(|s| Self { inner: s })
            }
            #[cfg(windows)]
            {
                Ok(Self {
                    inner: std::sync::Arc::clone(&self.inner),
                })
            }
            #[cfg(not(any(unix, windows)))]
            {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported platform",
                ))
            }
        }

        pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            #[cfg(unix)]
            {
                self.inner.set_read_timeout(dur)
            }
            #[cfg(windows)]
            {
                self.inner.set_read_timeout(dur)
            }
            #[cfg(not(any(unix, windows)))]
            {
                let _ = dur;
                Ok(())
            }
        }

        pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            #[cfg(unix)]
            {
                self.inner.set_write_timeout(dur)
            }
            #[cfg(windows)]
            {
                self.inner.set_write_timeout(dur)
            }
            #[cfg(not(any(unix, windows)))]
            {
                let _ = dur;
                Ok(())
            }
        }

        pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
            #[cfg(unix)]
            {
                self.inner.shutdown(how)
            }
            #[cfg(windows)]
            {
                self.inner.shutdown(how);
                Ok(())
            }
            #[cfg(not(any(unix, windows)))]
            {
                let _ = how;
                Ok(())
            }
        }
    }

    impl Read for IpcStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl Write for IpcStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            #[cfg(unix)]
            {
                self.inner.flush()
            }
            #[cfg(windows)]
            {
                Ok(())
            }
        }
    }

    /// Cross-platform local IPC listener (Unix domain socket or Windows Named Pipe).
    #[derive(Debug)]
    pub struct IpcListener {
        #[cfg(unix)]
        inner: UnixListener,
        #[cfg(windows)]
        inner: super::win_ipc::NamedPipeListener,
    }

    impl IpcListener {
        #[cfg(unix)]
        pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<Self> {
            let listener = UnixListener::bind(path)?;
            Ok(Self { inner: listener })
        }

        #[cfg(windows)]
        pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<Self> {
            let path_str = path.as_ref().to_string_lossy();
            let listener = super::win_ipc::NamedPipeListener::bind(&path_str)?;
            Ok(Self { inner: listener })
        }

        #[cfg(not(any(unix, windows)))]
        pub fn bind<P: AsRef<Path>>(_path: P) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported platform",
            ))
        }

        pub fn accept(&self) -> io::Result<(IpcStream, Principal)> {
            #[cfg(unix)]
            {
                let (stream, _) = self.inner.accept()?;
                let principal = peer_principal(&stream)?;
                Ok((IpcStream { inner: stream }, principal))
            }
            #[cfg(windows)]
            {
                let (file, principal) = self.inner.accept()?;
                Ok((IpcStream::from_file(file)?, principal))
            }
            #[cfg(not(any(unix, windows)))]
            {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported platform",
                ))
            }
        }
    }
}
pub use ipc::{IpcListener, IpcStream};

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
mod imp {
    use super::*;

    // uid_t/gid_t are u32 on all of macOS and the BSDs.
    extern "C" {
        fn getpeereid(fd: i32, euid: *mut u32, egid: *mut u32) -> i32;
    }

    pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
        let mut uid: u32 = 0;
        let mut gid: u32 = 0;
        // SAFETY: `as_raw_fd` returns a valid fd owned by `stream` (borrowed
        // for the duration of the call only); `uid`/`gid` are valid writable
        // out-pointers; getpeereid has no other contracts.
        let rc = unsafe { getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        if rc == 0 {
            Ok(uid)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use super::*;
    use std::ffi::c_void;
    use std::mem::MaybeUninit;

    const SOL_SOCKET: i32 = 1;
    const SO_PEERCRED: i32 = 17;

    #[repr(C)]
    struct Ucred {
        pid: i32,
        uid: u32,
        gid: u32,
    }

    extern "C" {
        fn getsockopt(
            fd: i32,
            level: i32,
            name: i32,
            value: *mut c_void,
            value_len: *mut u32,
        ) -> i32;
    }

    pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
        // SAFETY: `cred` is a valid writable out-buffer of `Ucred` size and
        // `len` is a valid in/out length pointer; the fd is borrowed from
        // `stream` for the call only. getsockopt(SO_PEERCRED) fills `cred`.
        let cred = unsafe {
            let mut cred = MaybeUninit::<Ucred>::uninit();
            let mut len = std::mem::size_of::<Ucred>() as u32;
            let rc = getsockopt(
                stream.as_raw_fd(),
                SOL_SOCKET,
                SO_PEERCRED,
                cred.as_mut_ptr().cast(),
                &mut len,
            );
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            if (len as usize) < std::mem::size_of::<Ucred>() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short SO_PEERCRED credential",
                ));
            }
            cred.assume_init()
        };
        Ok(cred.uid)
    }
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "linux",
    target_os = "android"
)))]
#[cfg(unix)]
mod imp {
    use super::*;

    #[cfg(unix)]
    pub fn peer_uid(_stream: &UnixStream) -> io::Result<u32> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer credentials not implemented on this platform",
        ))
    }
}

#[cfg(windows)]
mod win_rand {
    use std::ffi::c_void;
    use std::io;

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            hAlgorithm: *mut c_void,
            pbBuffer: *mut u8,
            cbBuffer: u32,
            dwFlags: u32,
        ) -> i32;
    }

    pub fn fill_random(buf: &mut [u8]) -> io::Result<()> {
        let len = u32::try_from(buf.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "random request too large"))?;
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                len,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("BCryptGenRandom failed with NTSTATUS 0x{status:08x}"),
            ))
        }
    }
}

#[cfg(windows)]
pub mod win_pipe {
    use super::Principal;
    use std::ffi::c_void;
    use std::io;

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            ProcessHandle: *mut c_void,
            DesiredAccess: u32,
            TokenHandle: *mut *mut c_void,
        ) -> i32;
        fn GetTokenInformation(
            TokenHandle: *mut c_void,
            TokenInformationClass: u32,
            TokenInformation: *mut c_void,
            TokenInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(Sid: *mut c_void, StringSid: *mut *mut u16) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetNamedPipeClientProcessId(Pipe: *mut c_void, ClientProcessId: *mut u32) -> i32;
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut c_void;
        fn CloseHandle(hObject: *mut c_void) -> i32;
        fn LocalFree(hMem: *mut c_void) -> *mut c_void;
    }

    /// # Safety
    /// `pipe` must be a live server-side handle for a connected named pipe.
    pub unsafe fn get_pipe_client_sid(pipe: *mut c_void) -> io::Result<Principal> {
        if pipe.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "null pipe handle",
            ));
        }
        unsafe {
            // The kernel supplies the connected client's PID. Resolve its
            // process token before admitting any request; failure denies it.
            let mut pid = 0;
            if GetNamedPipeClientProcessId(pipe, &mut pid) == 0 || pid == 0 {
                return Err(io::Error::last_os_error());
            }
            let process = OpenProcess(0x1000, 0, pid); // PROCESS_QUERY_LIMITED_INFORMATION
            if process.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut client_token: *mut c_void = std::ptr::null_mut();
            let open_res = OpenProcessToken(process, TOKEN_QUERY, &mut client_token);
            let open_error = io::Error::last_os_error();
            let mut current_pid = 0;
            let same_client =
                GetNamedPipeClientProcessId(pipe, &mut current_pid) != 0 && current_pid == pid;
            CloseHandle(process);
            if open_res == 0 || client_token.is_null() || !same_client {
                if !client_token.is_null() {
                    CloseHandle(client_token);
                }
                return Err(if same_client {
                    open_error
                } else {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "pipe client changed during SID lookup",
                    )
                });
            }

            let mut ret_len: u32 = 0;
            GetTokenInformation(
                client_token,
                TOKEN_USER_CLASS,
                std::ptr::null_mut(),
                0,
                &mut ret_len,
            );
            if ret_len < std::mem::size_of::<TokenUser>() as u32 || ret_len > 1024 {
                CloseHandle(client_token);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid token user length",
                ));
            }

            let mut buf = vec![0_u8; ret_len as usize];
            let get_info = GetTokenInformation(
                client_token,
                TOKEN_USER_CLASS,
                buf.as_mut_ptr().cast(),
                ret_len,
                &mut ret_len,
            );
            CloseHandle(client_token);

            if get_info == 0 {
                return Err(io::Error::last_os_error());
            }

            let token_user = std::ptr::read_unaligned(buf.as_ptr().cast::<TokenUser>());
            let mut sid_str_ptr: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(token_user.user.sid, &mut sid_str_ptr) == 0
                || sid_str_ptr.is_null()
            {
                return Err(io::Error::last_os_error());
            }

            let mut len = 0;
            while *sid_str_ptr.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(sid_str_ptr, len);
            let sid_string = String::from_utf16_lossy(slice);
            LocalFree(sid_str_ptr.cast());

            Ok(Principal::WindowsSid(sid_string))
        }
    }
}

#[cfg(windows)]
mod win_acl {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::Path;

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER: u32 = 1;
    const OWNER_SECURITY_INFORMATION: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 4;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
    const SE_FILE_OBJECT: u32 = 1;
    const SE_DACL_PROTECTED: u16 = 0x1000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

    #[repr(C)]
    struct SecurityAttributes {
        len: u32,
        descriptor: *mut c_void,
        inherit: i32,
    }

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[repr(C)]
    struct Acl {
        revision: u8,
        reserved: u8,
        size: u16,
        ace_count: u16,
        reserved2: u16,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
        fn GetTokenInformation(
            token: *mut c_void,
            class: u32,
            out: *mut c_void,
            len: u32,
            used: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            version: u32,
            out: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
        fn GetNamedSecurityInfoW(
            name: *const u16,
            object_type: u32,
            info: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            descriptor: *mut *mut c_void,
        ) -> u32;
        fn SetFileSecurityW(name: *const u16, info: u32, descriptor: *mut c_void) -> i32;
        fn GetSecurityDescriptorControl(
            descriptor: *mut c_void,
            control: *mut u16,
            revision: *mut u32,
        ) -> i32;
        fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
        fn EqualSid(a: *mut c_void, b: *mut c_void) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn LocalFree(ptr: *mut c_void) -> *mut c_void;
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            attrs: *mut SecurityAttributes,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        fn CreateDirectoryW(name: *const u16, attrs: *mut SecurityAttributes) -> i32;
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }

    fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
        text.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn current_sid<R>(f: impl FnOnce(*mut c_void) -> io::Result<R>) -> io::Result<R> {
        unsafe {
            let mut token = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0;
            GetTokenInformation(token, TOKEN_USER, std::ptr::null_mut(), 0, &mut len);
            if len < std::mem::size_of::<TokenUser>() as u32 || len > 1024 {
                CloseHandle(token);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid token user length",
                ));
            }
            let mut buf = vec![0u8; len as usize];
            let ok = GetTokenInformation(token, TOKEN_USER, buf.as_mut_ptr().cast(), len, &mut len);
            let err = io::Error::last_os_error();
            CloseHandle(token);
            if ok == 0 {
                return Err(err);
            }
            f(std::ptr::read_unaligned(buf.as_ptr().cast::<TokenUser>())
                .user
                .sid)
        }
    }

    fn owner_descriptor<R>(
        directory: bool,
        f: impl FnOnce(*mut SecurityAttributes) -> io::Result<R>,
    ) -> io::Result<R> {
        current_sid(|sid| unsafe {
            let mut sid_text = std::ptr::null_mut();
            if ConvertSidToStringSidW(sid, &mut sid_text) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0;
            while *sid_text.add(len) != 0 {
                len += 1;
            }
            let owner = String::from_utf16_lossy(std::slice::from_raw_parts(sid_text, len));
            LocalFree(sid_text.cast());
            // Protected DACL prevents inherited grants from widening access.
            let inheritance = if directory { "OICI" } else { "" };
            let sddl = format!("O:{owner}D:P(A;{inheritance};GA;;;{owner})");
            let mut descriptor = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl.as_ref()).as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut attrs = SecurityAttributes {
                len: std::mem::size_of::<SecurityAttributes>() as u32,
                descriptor,
                inherit: 0,
            };
            let result = f(&mut attrs);
            LocalFree(descriptor);
            result
        })
    }

    pub(super) fn with_owner_security_attributes<R>(
        f: impl FnOnce(*mut c_void) -> io::Result<R>,
    ) -> io::Result<R> {
        owner_descriptor(false, |attrs| f(attrs.cast()))
    }

    pub fn protect_owner_only(path: &Path) -> io::Result<()> {
        owner_descriptor(false, |attrs| unsafe {
            if SetFileSecurityW(
                wide(path.as_os_str()).as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                (*attrs).descriptor,
            ) == 0
            {
                Err(io::Error::last_os_error())
            } else {
                verify_owner_only(path)
            }
        })
    }

    pub fn verify_owner_only(path: &Path) -> io::Result<()> {
        let name = wide(path.as_os_str());
        current_sid(|current| unsafe {
            let mut owner = std::ptr::null_mut();
            let mut dacl = std::ptr::null_mut();
            let mut descriptor = std::ptr::null_mut();
            let status = GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            );
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            let result = (|| {
                if owner.is_null() || dacl.is_null() || EqualSid(owner, current) == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "private path owner or DACL missing",
                    ));
                }
                let mut control = 0;
                let mut revision = 0;
                if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
                    || control & SE_DACL_PROTECTED == 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "private path DACL inherits grants",
                    ));
                }
                let acl = &*(dacl.cast::<Acl>());
                if acl.ace_count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "private path DACL has no owner grant",
                    ));
                }
                for index in 0..u32::from(acl.ace_count) {
                    let mut ace = std::ptr::null_mut();
                    if GetAce(dacl, index, &mut ace) == 0 {
                        return Err(io::Error::last_os_error());
                    }
                    // ACCESS_ALLOWED_ACE: header(4), mask(4), SID starts at byte 8.
                    if *(ace.cast::<u8>()) != 0
                        || EqualSid(ace.cast::<u8>().add(8).cast(), current) == 0
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "private path grants another principal",
                        ));
                    }
                }
                Ok(())
            })();
            LocalFree(descriptor);
            result
        })
    }

    pub fn open_private_file_for_write(path: &Path) -> io::Result<std::fs::File> {
        owner_descriptor(false, |attrs| unsafe {
            let name = wide(path.as_os_str());
            let handle = CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                attrs,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(std::fs::File::from_raw_handle(handle))
            }
        })
    }

    pub fn create_private_dir_all(path: &Path) -> io::Result<()> {
        if path.exists() {
            return super::verify_private_dir_perms(path);
        }
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                create_private_dir_all(parent)?;
            }
        }
        owner_descriptor(true, |attrs| unsafe {
            let name = wide(path.as_os_str());
            if CreateDirectoryW(name.as_ptr(), attrs) == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        })
    }

    pub fn publish_dir_noreplace(from: &Path, to: &Path) -> io::Result<()> {
        unsafe {
            // MOVEFILE_WRITE_THROUGH, without REPLACE_EXISTING: existing
            // published output always wins, including concurrent creation.
            if MoveFileExW(
                wide(from.as_os_str()).as_ptr(),
                wide(to.as_os_str()).as_ptr(),
                0x8,
            ) == 0
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub(super) fn create_world_file(path: &Path) -> io::Result<()> {
        unsafe {
            let mut descriptor = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide("D:P(A;;GA;;;WD)".as_ref()).as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut attrs = SecurityAttributes {
                len: std::mem::size_of::<SecurityAttributes>() as u32,
                descriptor,
                inherit: 0,
            };
            let name = wide(path.as_os_str());
            let handle = CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                &mut attrs,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            );
            let error = io::Error::last_os_error();
            LocalFree(descriptor);
            if handle == INVALID_HANDLE_VALUE {
                return Err(error);
            }
            CloseHandle(handle);
            Ok(())
        }
    }
}

#[cfg(windows)]
mod win_serial {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    #[repr(C)]
    struct Dcb {
        len: u32,
        baud: u32,
        flags: u32,
        reserved: u16,
        xon_limit: u16,
        xoff_limit: u16,
        byte_size: u8,
        parity: u8,
        stop_bits: u8,
        xon: i8,
        xoff: i8,
        error: i8,
        eof: i8,
        evt: i8,
        reserved2: u16,
    }

    #[repr(C)]
    struct CommTimeouts {
        read_interval: u32,
        read_multiplier: u32,
        read_constant: u32,
        write_multiplier: u32,
        write_constant: u32,
    }

    #[repr(C)]
    struct CommStat {
        flags: u32,
        in_queue: u32,
        out_queue: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCommState(handle: *mut std::ffi::c_void, dcb: *mut Dcb) -> i32;
        fn SetCommState(handle: *mut std::ffi::c_void, dcb: *const Dcb) -> i32;
        fn SetCommTimeouts(handle: *mut std::ffi::c_void, timeouts: *const CommTimeouts) -> i32;
        fn ClearCommError(
            handle: *mut std::ffi::c_void,
            errors: *mut u32,
            stat: *mut CommStat,
        ) -> i32;
    }

    pub fn open(path: &Path) -> io::Result<File> {
        let name = path.to_string_lossy();
        let device = if name.len() >= 4
            && name
                .get(..3)
                .is_some_and(|head| head.eq_ignore_ascii_case("COM"))
            && name[3..].bytes().all(|b| b.is_ascii_digit())
        {
            format!(r"\\.\{name}")
        } else {
            name.into_owned()
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(device)?;
        unsafe {
            let handle = file.as_raw_handle();
            let mut dcb: Dcb = std::mem::zeroed();
            dcb.len = std::mem::size_of::<Dcb>() as u32;
            if GetCommState(handle, &mut dcb) == 0 {
                return Err(io::Error::last_os_error());
            }
            dcb.baud = 115_200;
            dcb.flags = 1 | 0x10 | 0x1000; // binary, DTR and RTS enabled; no software flow control
            dcb.byte_size = 8;
            dcb.parity = 0;
            dcb.stop_bits = 0;
            if SetCommState(handle, &dcb) == 0 {
                return Err(io::Error::last_os_error());
            }
            let timeouts = CommTimeouts {
                read_interval: u32::MAX,
                read_multiplier: 0,
                read_constant: 1_000,
                write_multiplier: 0,
                write_constant: 2_000,
            };
            if SetCommTimeouts(handle, &timeouts) == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(file)
    }

    pub fn idle_check(file: &File) -> io::Result<()> {
        unsafe {
            let mut errors = 0;
            let mut stat: CommStat = std::mem::zeroed();
            if ClearCommError(file.as_raw_handle(), &mut errors, &mut stat) == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(windows)]
pub mod win_ipc {
    use super::Principal;
    use std::ffi::c_void;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::net::Shutdown;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
    const PIPE_TYPE_BYTE: u32 = 0x00000000;
    const PIPE_READMODE_BYTE: u32 = 0x00000000;
    const PIPE_WAIT: u32 = 0x00000000;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x00000008;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const PIPE_NOWAIT: u32 = 1;
    const ERROR_BROKEN_PIPE: i32 = 109;
    const ERROR_NO_DATA: i32 = 232;
    const ERROR_PIPE_NOT_CONNECTED: i32 = 233;
    const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateNamedPipeW(
            lpName: *const u16,
            dwOpenMode: u32,
            dwPipeMode: u32,
            nMaxInstances: u32,
            nOutBufferSize: u32,
            nInBufferSize: u32,
            nDefaultTimeOut: u32,
            lpSecurityAttributes: *mut c_void,
        ) -> *mut c_void;

        fn ConnectNamedPipe(hNamedPipe: *mut c_void, lpOverlapped: *mut c_void) -> i32;
        fn SetNamedPipeHandleState(
            pipe: *mut c_void,
            mode: *mut u32,
            max_collection: *mut u32,
            collection_timeout: *mut u32,
        ) -> i32;
        fn GetLastError() -> u32;
    }

    #[derive(Debug)]
    pub struct PipeStream {
        file: File,
        read_timeout: Mutex<Option<Duration>>,
        write_timeout: Mutex<Option<Duration>>,
        read_closed: AtomicBool,
        write_closed: AtomicBool,
    }

    impl PipeStream {
        pub fn new(file: File) -> io::Result<Self> {
            let mut mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
            if unsafe {
                SetNamedPipeHandleState(
                    file.as_raw_handle(),
                    &mut mode,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                file,
                read_timeout: Mutex::new(None),
                write_timeout: Mutex::new(None),
                read_closed: AtomicBool::new(false),
                write_closed: AtomicBool::new(false),
            })
        }

        fn set_timeout(slot: &Mutex<Option<Duration>>, dur: Option<Duration>) -> io::Result<()> {
            if dur == Some(Duration::ZERO) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "zero pipe timeout",
                ));
            }
            *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = dur;
            Ok(())
        }

        pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            Self::set_timeout(&self.read_timeout, dur)
        }

        pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            Self::set_timeout(&self.write_timeout, dur)
        }

        pub fn shutdown(&self, how: Shutdown) {
            if matches!(how, Shutdown::Read | Shutdown::Both) {
                self.read_closed.store(true, Ordering::Release);
            }
            if matches!(how, Shutdown::Write | Shutdown::Both) {
                self.write_closed.store(true, Ordering::Release);
            }
        }

        fn wait_for_space(start: Instant, timeout: Option<Duration>) -> io::Result<()> {
            if timeout.is_some_and(|dur| start.elapsed() >= dur) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pipe I/O timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
            Ok(())
        }

        pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let timeout = *self
                .read_timeout
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let started = Instant::now();
            loop {
                if self.read_closed.load(Ordering::Acquire) {
                    return Ok(0);
                }
                match (&self.file).read(buf) {
                    Err(e) if e.raw_os_error() == Some(ERROR_NO_DATA) => {
                        Self::wait_for_space(started, timeout)?;
                    }
                    Err(e)
                        if matches!(
                            e.raw_os_error(),
                            Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED)
                        ) =>
                    {
                        return Ok(0);
                    }
                    result => return result,
                }
            }
        }

        pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let timeout = *self
                .write_timeout
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let started = Instant::now();
            loop {
                if self.write_closed.load(Ordering::Acquire) {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "pipe write closed",
                    ));
                }
                match (&self.file).write(buf) {
                    Ok(0) => Self::wait_for_space(started, timeout)?,
                    Err(e) if e.raw_os_error() == Some(ERROR_NO_DATA) => {
                        Self::wait_for_space(started, timeout)?;
                    }
                    result => return result,
                }
            }
        }
    }

    #[derive(Debug)]
    pub struct NamedPipeListener {
        pipe_name: Vec<u16>,
        first: Mutex<Option<File>>,
    }

    impl NamedPipeListener {
        pub fn bind(name: &str) -> io::Result<Self> {
            let full_name = normalize_pipe_name(name);
            let mut wide: Vec<u16> = full_name.encode_utf16().collect();
            wide.push(0);
            let first = Self::create_instance(&wide, true)?;
            Ok(Self {
                pipe_name: wide,
                first: Mutex::new(Some(first)),
            })
        }

        fn create_instance(name: &[u16], first: bool) -> io::Result<File> {
            super::win_acl::with_owner_security_attributes(|attrs| unsafe {
                let handle = CreateNamedPipeW(
                    name.as_ptr(),
                    PIPE_ACCESS_DUPLEX
                        | if first {
                            FILE_FLAG_FIRST_PIPE_INSTANCE
                        } else {
                            0
                        },
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    65536,
                    65536,
                    5000,
                    attrs,
                );
                if handle == INVALID_HANDLE_VALUE {
                    return Err(io::Error::last_os_error());
                }
                Ok(File::from_raw_handle(handle))
            })
        }

        pub fn accept(&self) -> io::Result<(File, Principal)> {
            let mut waiting = self.first.lock().expect("pipe listener poisoned");
            let file = match waiting.take() {
                Some(file) => file,
                None => Self::create_instance(&self.pipe_name, false)?,
            };
            let handle = file.as_raw_handle();
            unsafe {
                let connect_res = ConnectNamedPipe(handle, std::ptr::null_mut());
                if connect_res == 0 {
                    let err = GetLastError();
                    // 535 = ERROR_PIPE_CONNECTED
                    if err != 535 {
                        return Err(io::Error::from_raw_os_error(err as i32));
                    }
                }
                let principal = super::win_pipe::get_pipe_client_sid(handle)?;
                // Keep one server instance available while the daemon hands
                // this connection to a worker; clients never race a gap.
                let next = Self::create_instance(&self.pipe_name, false)?;
                *waiting = Some(next);
                Ok((file, principal))
            }
        }
    }

    pub fn connect_pipe(name: &str) -> io::Result<File> {
        if name.starts_with(r"\\") && !name.starts_with(r"\\.\pipe\") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "remote pipe address rejected",
            ));
        }
        let full_name = normalize_pipe_name(name);
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(full_name)
    }

    pub fn normalize_pipe_name(name: &str) -> String {
        if name.starts_with(r"\\.\pipe\") {
            name.to_string()
        } else {
            let clean = name.replace(['/', '\\', ':'], "-");
            format!(r"\\.\pipe\{clean}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_parsing_and_formatting() {
        let p_uid = "1001".parse::<Principal>().expect("parse uid");
        assert_eq!(p_uid, Principal::UnixUid(1001));
        assert_eq!(p_uid.to_string(), "1001");
        assert_eq!(p_uid.as_unix_uid(), Some(1001));
        assert_eq!(p_uid.as_windows_sid(), None);

        let p_uid_pref = "uid:1002".parse::<Principal>().expect("parse uid prefix");
        assert_eq!(p_uid_pref, Principal::UnixUid(1002));

        let p_sid = "S-1-5-21-3623811015-3361044348-30300820-1013"
            .parse::<Principal>()
            .expect("parse sid");
        assert_eq!(
            p_sid,
            Principal::WindowsSid("S-1-5-21-3623811015-3361044348-30300820-1013".to_string())
        );
        assert_eq!(
            p_sid.to_string(),
            "S-1-5-21-3623811015-3361044348-30300820-1013"
        );
        assert_eq!(
            p_sid.as_windows_sid(),
            Some("S-1-5-21-3623811015-3361044348-30300820-1013")
        );
        assert_eq!(p_sid.as_unix_uid(), None);

        let p_sid_pref = "sid:S-1-5-18"
            .parse::<Principal>()
            .expect("parse sid prefix");
        assert_eq!(p_sid_pref, Principal::WindowsSid("S-1-5-18".to_string()));

        assert!("invalid".parse::<Principal>().is_err());
    }

    #[test]
    fn fill_random_draws_bytes() {
        let mut buf = [0_u8; 32];
        fill_random(&mut buf).expect("fill_random succeeds");
        assert_ne!(buf, [0_u8; 32]);
    }

    #[cfg(windows)]
    #[test]
    fn named_pipe_authenticates_local_sid_and_rejects_remote_address() {
        use std::io::{Read, Write};
        let name = format!(r"\\.\pipe\routeloom-auth-test-{}", std::process::id());
        let listener = IpcListener::bind(&name).expect("bind pipe");
        assert!(
            IpcListener::bind(&name).is_err(),
            "pipe name cannot be taken twice"
        );
        let server = std::thread::spawn(move || {
            let (mut stream, principal) = listener.accept().expect("accept authenticated client");
            let mut byte = [0];
            stream.read_exact(&mut byte).expect("read");
            assert_eq!(byte, [42]);
            principal
        });
        let mut client = (0..100)
            .find_map(|_| match IpcStream::connect(&name) {
                Ok(stream) => Some(stream),
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    None
                }
            })
            .expect("connect own pipe");
        client.write_all(&[42]).expect("write");
        let principal = server.join().expect("server");
        assert!(matches!(principal, Principal::WindowsSid(ref sid) if sid.starts_with("S-1-")));
        assert!(IpcStream::connect(r"\\localhost\pipe\routeloom-auth-test").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn named_pipe_rejects_a_non_owner_token() {
        #[link(name = "advapi32")]
        extern "system" {
            fn ImpersonateAnonymousToken(thread: *mut std::ffi::c_void) -> i32;
            fn RevertToSelf() -> i32;
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentThread() -> *mut std::ffi::c_void;
        }
        let name = format!(r"\\.\pipe\routeloom-nonowner-test-{}", std::process::id());
        let _listener = IpcListener::bind(&name).expect("bind owner-only pipe");
        std::thread::spawn(move || unsafe {
            assert_ne!(ImpersonateAnonymousToken(GetCurrentThread()), 0);
            let result = IpcStream::connect(&name);
            assert_ne!(RevertToSelf(), 0);
            assert!(result.is_err(), "anonymous non-owner opened the pipe");
        })
        .join()
        .unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn named_pipe_read_and_write_timeouts_are_enforced() {
        use std::io::{Read, Write};
        use std::time::Duration;

        let (mut client, mut server) = IpcStream::pair().unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let (read_tx, read_rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut byte = [0];
            read_tx
                .send(server.read(&mut byte).map_err(|e| e.kind()))
                .unwrap();
            server
        });
        assert_eq!(
            read_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Err(io::ErrorKind::TimedOut)
        );
        let _server = reader.join().unwrap();

        client
            .set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let (write_tx, write_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let block = [7u8; 131_072];
            loop {
                if let Err(error) = client.write_all(&block) {
                    write_tx.send(error.kind()).unwrap();
                    break;
                }
            }
        });
        assert_eq!(
            write_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            io::ErrorKind::TimedOut
        );
        writer.join().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn named_pipe_peer_close_reads_as_eof() {
        use std::io::Read;
        use std::time::Duration;

        let (mut client, server) = IpcStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        drop(server);
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn private_file_rejects_other_user_grant() {
        let dir = tempfile_dir();
        let private = dir.join("private.key");
        open_private_file_for_write(&private).expect("create owner-only key");
        verify_private_file_perms(&private).expect("owner-only key accepted");
        let public = dir.join("public.key");
        win_acl::create_world_file(&public).expect("create permissive fixture");
        assert_eq!(
            verify_private_file_perms(&public).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let _ = std::fs::remove_file(private);
        let _ = std::fs::remove_file(public);
        let _ = std::fs::remove_dir(dir);
    }

    #[cfg(unix)]
    #[test]
    fn socketpair_peer_resolves_to_own_uid() {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let uid = peer_uid(&a).expect("peer uid resolvable on this platform");
        let expected = String::from_utf8(
            std::process::Command::new("id")
                .arg("-u")
                .output()
                .expect("id -u")
                .stdout,
        )
        .expect("id output utf-8");
        assert_eq!(uid.to_string(), expected.trim());

        let principal = peer_principal(&a).expect("peer principal resolvable");
        assert_eq!(principal, Principal::UnixUid(uid));
    }

    #[cfg(unix)]
    #[test]
    fn ipc_stream_and_listener_roundtrip() {
        use std::io::{Read, Write};
        let socket_dir = tempfile_dir();
        let socket_path = socket_dir.join("test-ipc.sock");
        let listener = IpcListener::bind(&socket_path).expect("bind ipc listener");

        let handle = std::thread::spawn(move || {
            let (mut stream, principal) = listener.accept().expect("accept ipc client");
            let mut buf = [0_u8; 4];
            stream.read_exact(&mut buf).expect("read from client");
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").expect("write to client");
            principal
        });

        let mut client = IpcStream::connect(&socket_path).expect("connect ipc stream");
        client.write_all(b"ping").expect("write ping");
        let mut resp = [0_u8; 4];
        client.read_exact(&mut resp).expect("read pong");
        assert_eq!(&resp, b"pong");

        let principal = handle.join().expect("join server thread");
        let expected_uid: u32 = String::from_utf8(
            std::process::Command::new("id")
                .arg("-u")
                .output()
                .expect("id -u")
                .stdout,
        )
        .expect("id utf8")
        .trim()
        .parse()
        .expect("parse uid");
        assert_eq!(principal, Principal::UnixUid(expected_uid));

        let _ = std::fs::remove_file(socket_path);
        let _ = std::fs::remove_dir(socket_dir);
    }

    #[test]
    fn file_lock_roundtrip() {
        let dir = tempfile_dir();
        let path = dir.join("test.lock");
        let file1 = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .expect("open file1");

        let acquired = try_lock_file_exclusive(&file1).expect("lock file1");
        assert!(acquired);

        let file2 = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open file2");
        let acquired2 = try_lock_file_exclusive(&file2).expect("try lock file2");
        assert!(!acquired2, "second lock must fail while first is held");

        unlock_file(&file1).expect("unlock file1");

        let acquired3 = try_lock_file_exclusive(&file2).expect("relock file2");
        assert!(acquired3, "lock on file2 must succeed after file1 unlocked");
        unlock_file(&file2).expect("unlock file2");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        let rnd: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(12345);
        d.push(format!("rl-test-ipc-{}", rnd));
        let _ = std::fs::create_dir_all(&d);
        d
    }
}
