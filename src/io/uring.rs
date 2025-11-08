// Numan Thabit 2025
// io/uring.rs - io_uring backend, MSG_ZEROCOPY
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoUringSupport {
    Available,
    Disabled,
    Unsupported,
}

pub fn detect_support() -> IoUringSupport {
    #[cfg(target_os = "linux")]
    {
        let path = Path::new("/proc/sys/kernel/io_uring_disabled");
        match fs::read_to_string(path) {
            Ok(contents) => {
                if contents.trim() == "0" {
                    IoUringSupport::Available
                } else {
                    IoUringSupport::Disabled
                }
            }
            Err(_) => IoUringSupport::Available,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        IoUringSupport::Unsupported
    }
}

pub fn enable_msg_zerocopy() -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        Ok(true)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(false)
    }
}

