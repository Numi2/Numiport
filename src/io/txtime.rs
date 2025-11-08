// Numan Thabit 2025
// io/txtime.rs - SO_TXTIME + ETF helpers and error-queue reader
use std::io;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GuardDeltaController {
    min_ns: u64,
    max_ns: u64,
    step_ns: u64,
    current_ns: u64,
}

impl GuardDeltaController {
    pub fn new(min_ns: u64, max_ns: u64, initial_ns: u64) -> Self {
        let step = ((max_ns - min_ns) / 16).max(50_000);
        Self {
            min_ns,
            max_ns,
            step_ns: step,
            current_ns: initial_ns.clamp(min_ns, max_ns),
        }
    }

    pub fn current(&self) -> Duration {
        Duration::from_nanos(self.current_ns)
    }

    pub fn adjust(&mut self, late_drop_detected: bool) -> Duration {
        if late_drop_detected {
            self.current_ns = (self.current_ns + self.step_ns).min(self.max_ns);
        } else if self.current_ns > self.min_ns {
            self.current_ns = self.current_ns.saturating_sub(self.step_ns);
            if self.current_ns < self.min_ns {
                self.current_ns = self.min_ns;
            }
        }
        self.current()
    }
}

#[cfg(target_os = "linux")]
mod linux_txtime {
    use super::*;
    use std::mem;
    use std::os::fd::RawFd;

    const SO_TXTIME: libc::c_int = 61;
    const SOF_TXTIME_REPORT_ERRORS: u32 = 1;

    #[repr(C)]
    struct SockTxtime {
        clockid: libc::clockid_t,
        flags: u32,
        txtime: u64,
    }

    pub fn enable_txtime(fd: RawFd, guard_delta: Duration) -> io::Result<()> {
        let cfg = SockTxtime {
            clockid: libc::CLOCK_TAI,
            flags: SOF_TXTIME_REPORT_ERRORS,
            txtime: guard_delta.as_nanos() as u64,
        };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_TXTIME,
                &cfg as *const _ as *const libc::c_void,
                mem::size_of::<SockTxtime>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod linux_txtime {
    use super::*;
    use std::os::fd::RawFd;

    pub fn enable_txtime(_fd: RawFd, _guard_delta: Duration) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SO_TXTIME not supported on this platform",
        ))
    }
}

pub use linux_txtime::enable_txtime;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_delta_adjusts() {
        let mut ctrl = GuardDeltaController::new(200_000, 2_000_000, 500_000);
        assert_eq!(ctrl.current().as_nanos(), 500_000);
        ctrl.adjust(true);
        assert!(ctrl.current().as_nanos() >= 500_000);
        ctrl.adjust(false);
        assert!(ctrl.current().as_nanos() >= 200_000);
    }
}

