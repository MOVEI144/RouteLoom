//! OS-level peer credentials for Unix-domain socket peers.
//!
//! This crate is the *only* unsafe FFI boundary in the host workspace (the
//! workspace lint `unsafe_code = "forbid"` is deliberately not inherited
//! here — see Cargo.toml). `std` still marks `UnixStream::peer_cred`
//! unstable, so the daemon resolves the IPC principal's uid through the
//! platform syscalls directly:
//!
//! - macOS / BSD: `getpeereid(fd, &mut uid, &mut gid)`
//! - Linux / Android: `getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &mut ucred, …)`
//!
//! Everything else (request routing, ACL decisions) lives in the safe
//! `routeloom-host` crate — a peer uid is only ever an *input* there, never
//! trusted without the ACL check.

use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

/// Returns the effective uid of the process on the other end of `stream`.
///
/// Fails with `io::ErrorKind::Unsupported` on unix targets with no
/// implemented credential mechanism — callers must treat that as "principal
/// unknown", i.e. default-deny for privileged IPC methods.
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    imp::peer_uid(stream)
}

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
mod imp {
    use super::*;

    pub fn peer_uid(_stream: &UnixStream) -> io::Result<u32> {
        // No certified credential mechanism on this target. Per the design
        // contract the daemon must default-deny privileged API1 methods for
        // such peers rather than fabricate an identity.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer credentials not implemented on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
