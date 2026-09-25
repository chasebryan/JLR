//! The only module in this crate that contains `unsafe` code.
//!
//! Every function is a thin wrapper around one system call, checks the
//! return value, and documents why the call is sound. Nothing here makes
//! policy decisions.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// `MFD_EXEC`: request an executable memfd (Linux 6.3+). Defined here because
/// older libc bindings do not export it.
const MFD_EXEC: libc::c_uint = 0x0010;

/// Creates a sealable, close-on-exec memfd that may be executed.
///
/// Kernels older than 6.3 reject `MFD_EXEC` with `EINVAL`; the call is then
/// repeated without it, which those kernels treat as executable by default.
pub fn memfd_exec(name: &str) -> io::Result<File> {
    let cname = CString::new(name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let base = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    for flags in [base | MFD_EXEC, base] {
        // SAFETY: `cname` is a valid NUL-terminated string that outlives the call;
        // memfd_create has no other pointer arguments.
        let fd = unsafe { libc::syscall(libc::SYS_memfd_create, cname.as_ptr(), flags) };
        if fd >= 0 {
            // SAFETY: the kernel just returned this descriptor, so we own it exactly once.
            return Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd as RawFd) }));
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(err);
        }
    }
    Err(io::Error::from_raw_os_error(libc::EINVAL))
}

/// Arranges for two descriptors to appear at fixed numbers `a` and `b` in the
/// current process, with close-on-exec cleared, even if the sources already
/// occupy those numbers.
///
/// Intended for a `pre_exec` hook, where only async-signal-safe calls are
/// allowed; `fcntl` and `dup2` are.
pub fn place_fds(src_a: RawFd, a: RawFd, src_b: RawFd, b: RawFd) -> io::Result<()> {
    // Move both sources out of the way of the targets first.
    // SAFETY: F_DUPFD takes integers only; an invalid descriptor yields EBADF.
    let hi_a = unsafe { libc::fcntl(src_a, libc::F_DUPFD, 32) };
    // SAFETY: as above.
    let hi_b = unsafe { libc::fcntl(src_b, libc::F_DUPFD, 32) };
    if hi_a < 0 || hi_b < 0 {
        return Err(io::Error::last_os_error());
    }
    for (from, to) in [(hi_a, a), (hi_b, b)] {
        // SAFETY: dup2 takes two integers and touches no memory.
        if unsafe { libc::dup2(from, to) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fcntl(F_SETFD) takes integers only.
        if unsafe { libc::fcntl(to, libc::F_SETFD, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: closing a descriptor we just created above.
        unsafe { libc::close(from) };
    }
    Ok(())
}

/// Takes ownership of an inherited descriptor after checking that it is open.
///
/// # Safety
/// The caller must own `fd` (it must not be used or closed elsewhere).
pub unsafe fn adopt_fd(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: fcntl(F_GETFD) takes integers only and tells us whether `fd` is open.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor is open (checked above) and the caller guarantees ownership.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Brings the loopback interface up inside the current network namespace.
///
/// Requires `CAP_NET_ADMIN` in the namespace's owning user namespace.
pub fn loopback_up() -> io::Result<()> {
    // SAFETY: socket() takes integers only.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` was just returned by socket() and is owned here.
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: an all-zero `ifreq` is a valid value for this plain-data C struct.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in b"lo\0".iter().enumerate() {
        req.ifr_name[i] = *b as libc::c_char;
    }
    // SAFETY: `req` is a valid ifreq for SIOCGIFFLAGS; the kernel writes its flags field.
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS, &mut req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: after a successful SIOCGIFFLAGS the flags member of the union is initialised.
    unsafe {
        req.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    }
    // SAFETY: `req` is a valid ifreq for SIOCSIFFLAGS.
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS, &req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The kernel release string, from `uname(2)`.
pub fn kernel_release() -> String {
    // SAFETY: an all-zero `utsname` is a valid value for this plain-data C struct.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `u` is a valid, writable utsname.
    if unsafe { libc::uname(&mut u) } != 0 {
        return "unknown".into();
    }
    // SAFETY: uname NUL-terminates each field within the fixed-size arrays.
    let c = unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) };
    c.to_string_lossy().into_owned()
}

/// Effective user and group ids of this process.
pub fn effective_ids() -> (u32, u32) {
    // SAFETY: geteuid and getegid take no arguments and cannot fail.
    unsafe { (libc::geteuid(), libc::getegid()) }
}
