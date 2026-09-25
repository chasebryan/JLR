//! System-level helpers for the initramfs: loop devices and reboot.
//!
//! This is the only module with `unsafe`. Each block states why it is sound.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;
const LOOP_SET_FD: libc::c_ulong = 0x4C00;
const LOOP_CLR_FD: libc::c_ulong = 0x4C01;

/// Attaches `backing` to a free loop device and returns its path.
///
/// `backing` may be a memfd, which is how the verified image stays in RAM.
pub fn loop_attach(backing: &File) -> io::Result<String> {
    let ctl = File::options().read(true).write(true).open("/dev/loop-control")?;
    // SAFETY: LOOP_CTL_GET_FREE takes no argument and returns a device number or -1.
    let n = unsafe { libc::ioctl(ctl.as_raw_fd(), LOOP_CTL_GET_FREE as _) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let path = format!("/dev/loop{n}");
    let dev = File::options().read(true).write(true).open(&path)?;
    // SAFETY: LOOP_SET_FD takes a file descriptor by value; `backing` is open for the call.
    let r = unsafe { libc::ioctl(dev.as_raw_fd(), LOOP_SET_FD as _, backing.as_raw_fd()) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(path)
}

/// Detaches a loop device.
pub fn loop_detach(path: &str) -> io::Result<()> {
    let dev = File::options().read(true).write(true).open(path)?;
    // SAFETY: LOOP_CLR_FD takes no argument.
    if unsafe { libc::ioctl(dev.as_raw_fd(), LOOP_CLR_FD as _) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Powers the machine off. Never returns on success.
pub fn poweroff() -> io::Error {
    // SAFETY: sync() and reboot() take integers only. reboot(POWER_OFF) does not return on success.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
    io::Error::last_os_error()
}

/// Restarts the machine. Never returns on success.
pub fn restart() -> io::Error {
    // SAFETY: as for `poweroff`.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
    }
    io::Error::last_os_error()
}
