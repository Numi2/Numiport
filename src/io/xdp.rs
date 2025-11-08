// Numan Thabit 2025
// io/xdp.rs - AF_XDP backend
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpSupport {
    Available,
    Unsupported,
}

pub fn detect_support() -> XdpSupport {
    #[cfg(target_os = "linux")]
    {
        XdpSupport::Available
    }

    #[cfg(not(target_os = "linux"))]
    {
        XdpSupport::Unsupported
    }
}

pub fn create_umem() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "AF_XDP not supported",
        ))
    }
}

