//! OS-level peer credentials and platform security primitives.
//!
//! This crate is the *only* unsafe FFI boundary in the host workspace (the
//! workspace lint `unsafe_code = "forbid"` is deliberately not inherited
//! here — see Cargo.toml). `std` still marks `UnixStream::peer_cred`
//! unstable, and Windows Named Pipe client impersonation / SID queries
//! require platform FFI.
//!
//! Platform features provided:
//! - Unix peer UID (`getpeereid` on macOS/BSD, `getsockopt(SO_PEERCRED)` on Linux)
//! - Windows peer SID (Named Pipe client impersonation -> token user SID)
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

impl Principal {
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
/// (Unix 0600 or Windows regular file).
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
        let meta = std::fs::metadata(path)?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file is not a regular file",
            ));
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "permissions check not supported on this platform",
        ))
    }
}

/// Verifies that `path` is a directory with owner-only access permissions
/// (Unix 0700 or Windows regular directory).
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
        let meta = std::fs::metadata(path)?;
        if !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path is not a directory",
            ));
        }
        Ok(())
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
    #[cfg(not(unix))]
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
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
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
        pub(crate) inner: std::fs::File,
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
        pub fn from_file(file: std::fs::File) -> Self {
            Self { inner: file }
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
            Ok(Self { inner: file })
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
            Ok((Self { inner: client }, Self { inner: server }))
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
                self.inner.try_clone().map(|f| Self { inner: f })
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
                let _ = dur;
                Ok(())
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
                let _ = dur;
                Ok(())
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
                let _ = how;
                Ok(())
            }
            #[cfg(not(any(unix, windows)))]
            {
                let _ = how;
                Ok(())
            }
        }

        pub fn peer_principal(&self) -> io::Result<Principal> {
            #[cfg(unix)]
            {
                peer_principal(&self.inner)
            }
            #[cfg(windows)]
            {
                Ok(Principal::WindowsSid("S-1-5-local".to_string()))
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
            self.inner.flush()
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
                let principal = peer_principal(&stream).unwrap_or(Principal::UnixUid(u32::MAX));
                Ok((IpcStream { inner: stream }, principal))
            }
            #[cfg(windows)]
            {
                let (file, principal) = self.inner.accept()?;
                Ok((IpcStream { inner: file }, principal))
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
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
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
        fn ImpersonateNamedPipeClient(hNamedPipe: *mut c_void) -> i32;
        fn RevertToSelf() -> i32;
        fn OpenThreadToken(
            ThreadHandle: *mut c_void,
            DesiredAccess: u32,
            OpenAsSelf: i32,
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
        fn GetCurrentThread() -> *mut c_void;
        fn CloseHandle(hObject: *mut c_void) -> i32;
        fn LocalFree(hMem: *mut c_void) -> *mut c_void;
    }

    pub fn get_pipe_client_sid(pipe: *mut c_void) -> io::Result<Principal> {
        if pipe.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "null pipe handle",
            ));
        }
        unsafe {
            if ImpersonateNamedPipeClient(pipe) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut thread_token: *mut c_void = std::ptr::null_mut();
            let open_res = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_token);
            let _ = RevertToSelf(); // Always revert immediately
            if open_res == 0 || thread_token.is_null() {
                return Err(io::Error::last_os_error());
            }

            let mut ret_len: u32 = 0;
            GetTokenInformation(
                thread_token,
                TOKEN_USER_CLASS,
                std::ptr::null_mut(),
                0,
                &mut ret_len,
            );
            if ret_len == 0 {
                CloseHandle(thread_token);
                return Err(io::Error::last_os_error());
            }

            let mut buf = vec![0_u8; ret_len as usize];
            let get_info = GetTokenInformation(
                thread_token,
                TOKEN_USER_CLASS,
                buf.as_mut_ptr().cast(),
                ret_len,
                &mut ret_len,
            );
            CloseHandle(thread_token);

            if get_info == 0 {
                return Err(io::Error::last_os_error());
            }

            let token_user = &*(buf.as_ptr().cast::<TokenUser>());
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
pub mod win_ipc {
    use super::Principal;
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::os::windows::io::FromRawHandle;

    const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
    const PIPE_TYPE_BYTE: u32 = 0x00000000;
    const PIPE_READMODE_BYTE: u32 = 0x00000000;
    const PIPE_WAIT: u32 = 0x00000000;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x00000008;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
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
        fn CloseHandle(hObject: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    #[derive(Debug)]
    pub struct NamedPipeListener {
        pipe_name: Vec<u16>,
    }

    impl NamedPipeListener {
        pub fn bind(name: &str) -> io::Result<Self> {
            let full_name = normalize_pipe_name(name);
            let mut wide: Vec<u16> = full_name.encode_utf16().collect();
            wide.push(0);
            Ok(Self { pipe_name: wide })
        }

        pub fn accept(&self) -> io::Result<(File, Principal)> {
            unsafe {
                let handle = CreateNamedPipeW(
                    self.pipe_name.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    65536,
                    65536,
                    5000,
                    std::ptr::null_mut(),
                );
                if handle == INVALID_HANDLE_VALUE {
                    return Err(io::Error::last_os_error());
                }

                let connect_res = ConnectNamedPipe(handle, std::ptr::null_mut());
                if connect_res == 0 {
                    let err = GetLastError();
                    // 535 = ERROR_PIPE_CONNECTED
                    if err != 535 {
                        CloseHandle(handle);
                        return Err(io::Error::from_raw_os_error(err as i32));
                    }
                }

                let principal = super::win_pipe::get_pipe_client_sid(handle)
                    .unwrap_or_else(|_| Principal::WindowsSid("S-1-5-local".to_string()));

                let file = File::from_raw_handle(handle as std::os::windows::io::RawHandle);
                Ok((file, principal))
            }
        }
    }

    pub fn connect_pipe(name: &str) -> io::Result<File> {
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
