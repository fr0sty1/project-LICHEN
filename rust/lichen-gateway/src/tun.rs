//! Linux TUN device management.
//!
//! Opens `/dev/net/tun`, creates a TUN interface (no packet-info header),
//! and exposes async read/write. Requires `CAP_NET_ADMIN` or root.

use std::{
    io,
    os::unix::io::{AsRawFd, FromRawFd, OwnedFd},
};
use tokio::io::unix::AsyncFd;
use tracing::info;

// TUNSETIFF ioctl number from <linux/if_tun.h>: _IOW('T', 202, int) = 0x400454CA
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000; // suppress 4-byte packet-info header

/// Matches Linux `struct ifreq` from <linux/if.h> for ioctl ABI compatibility.
///
/// The kernel struct is 40 bytes: 16-byte `ifr_name` + 24-byte union (`ifr_ifru`).
/// We only need `ifr_flags` (2 bytes) from the union, so we pad the remaining
/// 22 bytes to preserve the struct size the kernel expects.
#[repr(C)]
struct Ifreq {
    ifr_name: [u8; 16],
    ifr_flags: libc::c_short,
    _pad: [u8; 22], // remainder of 24-byte ifr_ifru union
}

/// An async Linux TUN device.
#[derive(Debug)]
pub struct TunDevice {
    inner: AsyncFd<OwnedFd>,
    pub name: String,
}

impl TunDevice {
    /// Create and open a TUN interface named `name` (e.g. `"lichen0"`).
    pub fn open(name: &str) -> io::Result<Self> {
        // SAFETY: `c"/dev/net/tun"` is a valid null-terminated C string; `O_RDWR` is a valid
        // libc flag; the fd returned is checked for validity (< 0) immediately below.
        let fd = unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr() as *const libc::c_char,
                libc::O_RDWR,
            )
        };
        if fd < 0 {
            let e = io::Error::last_os_error();
            // Show actual error first, then suggest common causes based on error kind.
            let hint = match e.kind() {
                io::ErrorKind::NotFound => "device node missing (is tun module loaded?)",
                io::ErrorKind::PermissionDenied => "requires CAP_NET_ADMIN or root",
                _ => "check system logs for details",
            };
            return Err(io::Error::new(
                e.kind(),
                format!("failed to open /dev/net/tun: {e} ({hint})"),
            ));
        }

        let mut ifr = Ifreq {
            ifr_name: [0; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        let nb = name.len().min(15);
        ifr.ifr_name[..nb].copy_from_slice(&name.as_bytes()[..nb]);

        // SAFETY: `fd` is a valid file descriptor (checked above); `TUNSETIFF` is a valid ioctl
        // number; `ifr` is a properly initialised `Ifreq` struct with matching ABI layout (#[repr(C)]).
        let rc = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr as *const Ifreq as *const libc::c_void) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            // SAFETY: `fd` is a valid file descriptor (ioctl succeeded); no other thread is
            // using it concurrently during this error path; we are about to abandon it.
            unsafe { libc::close(fd) };
            return Err(io::Error::new(
                e.kind(),
                format!("TUNSETIFF ioctl failed for interface '{name}': {e}"),
            ));
        }

        // Must be non-blocking for tokio AsyncFd.
        // SAFETY: `fd` is valid and owned by this thread; `F_GETFL` has no preconditions.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        // SAFETY: `fd` is valid; `fl` was just retrieved from `F_GETFL` and `O_NONBLOCK` is
        // a valid flag; the result is checked immediately below.
        if fl < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) } < 0 {
            let e = io::Error::last_os_error();
            // SAFETY: same as above — `fd` is still valid and owned; no concurrent close.
            unsafe { libc::close(fd) };
            return Err(io::Error::new(
                e.kind(),
                format!("failed to set O_NONBLOCK on TUN fd: {e}"),
            ));
        }

        // SAFETY: `fd` is a valid, owned file descriptor; `OwnedFd::from_raw_fd` takes ownership
        // and will close it on drop — no other code holds a reference to this fd.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        info!(name, "TUN device opened");
        Ok(Self {
            inner: AsyncFd::new(owned)?,
            name: name.to_owned(),
        })
    }

    /// Read one IPv6 packet from the TUN device.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| {
                // SAFETY: `inner.as_raw_fd()` returns the valid fd owned by `self.inner`;
                // `buf` is a mutable slice, so `as_mut_ptr()` is valid for `buf.len()` bytes;
                // the return value is checked for errors (< 0) immediately.
                let n = unsafe {
                    libc::read(
                        inner.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    Err(io::Error::new(e.kind(), format!("TUN read failed: {e}")))
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one IPv6 packet to the TUN device (injects into the kernel).
    pub async fn send(&self, buf: &[u8]) -> io::Result<()> {
        if buf.len() > 1500 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet exceeds MTU",
            ));
        }
        let mut written = 0usize;
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| {
                // SAFETY: `inner.as_raw_fd()` is a valid fd; `buf.as_ptr().add(written)` is
                // within the bounds of `buf` because `written < buf.len()` (we only loop when
                // `written < buf.len()` and `written` is always in-bounds); the return value
                // is checked for errors.
                let n = unsafe {
                    libc::write(
                        inner.as_raw_fd(),
                        buf.as_ptr().add(written) as *const libc::c_void,
                        buf.len() - written,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else if n == 0 {
                    Err(io::Error::new(io::ErrorKind::WriteZero, "TUN write returned 0"))
                } else {
                    written += n as usize;
                    if written == buf.len() {
                        Ok(())
                    } else {
                        Err(io::ErrorKind::WouldBlock.into())
                    }
                }
            }) {
                Ok(r) => return r,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("TUN write failed after {written}/{} bytes: {e}", buf.len()),
                    ))
                }
            }
        }
    }
}

fn advance_written(written: &mut usize, n: usize) -> io::Result<()> {
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "TUN write returned 0 bytes",
        ));
    }
    *written += n;
    Ok(())
}

/// Bring the TUN device up and assign a gateway address from `prefix`.
///
/// Derives the gateway address by replacing the trailing `::` of the prefix
/// with `::1` (e.g. `fd00:1::/48` → gateway `fd00:1::1/48`).
///
/// Runs `ip` commands; requires `CAP_NET_ADMIN` or root.
pub fn configure(name: &str, prefix: &str) -> io::Result<()> {
    let gw_addr = gateway_addr(prefix)?;
    run_ip(&["link", "set", name, "up"])?;
    run_ip(&["-6", "addr", "add", &gw_addr, "dev", name])?;
    run_ip(&["-6", "route", "add", prefix, "dev", name])?;
    info!(name, gw_addr, prefix, "TUN device configured");
    Ok(())
}

fn gateway_addr(prefix: &str) -> io::Result<String> {
    let slash = prefix.rfind('/').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "prefix must include /length")
    })?;
    let base = &prefix[..slash]; // e.g. "fd00:1::"
    let len = &prefix[slash + 1..]; // e.g. "48"
    if !base.ends_with("::") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "prefix base must end with :: (e.g. fd00:1::/48)",
        ));
    }
    Ok(format!("{}1/{}", base, len)) // "fd00:1::1/48"
}

fn run_ip(args: &[&str]) -> io::Result<()> {
    let status = std::process::Command::new("ip").args(args).status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "ip {} exited {:?}",
            args.join(" "),
            status.code()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_addr_typical() {
        assert_eq!(gateway_addr("fd00:1::/48").unwrap(), "fd00:1::1/48");
        assert_eq!(
            gateway_addr("fd00:lichen:1::/64").unwrap(),
            "fd00:lichen:1::1/64"
        );
    }

    #[test]
    fn gateway_addr_no_slash() {
        assert!(gateway_addr("fd00:1::").is_err());
    }

    #[test]
    fn gateway_addr_no_double_colon() {
        assert!(gateway_addr("fd00:1:0:0/48").is_err());
    }

    #[test]
    fn zero_write_fails_without_progress() {
        let mut written = 0;
        let error = advance_written(&mut written, 0).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert_eq!(written, 0);
    }
}
