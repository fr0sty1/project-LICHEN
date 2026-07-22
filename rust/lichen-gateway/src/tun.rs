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

        let rc = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr as *const Ifreq as *const libc::c_void) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(io::Error::new(
                e.kind(),
                format!("TUNSETIFF ioctl failed for interface '{name}': {e}"),
            ));
        }

        // Must be non-blocking for tokio AsyncFd.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if fl < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) } < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(io::Error::new(
                e.kind(),
                format!("failed to set O_NONBLOCK on TUN fd: {e}"),
            ));
        }

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
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(
                        inner.as_raw_fd(),
                        buf.as_ptr() as *const libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    Err(io::Error::new(
                        e.kind(),
                        format!("TUN write failed ({} bytes): {e}", buf.len()),
                    ))
                } else if n as usize != buf.len() {
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        "partial TUN write",
                    ))
                } else {
                    Ok(())
                }
            }) {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }
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
}
