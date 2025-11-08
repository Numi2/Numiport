// Numan Thabit 2025
// io/udp.rs - sendmmsg/recvmmsg, UDP_SEGMENT, ECN read
use std::collections::VecDeque;
use std::io::{self, IoSlice};
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;

const DEFAULT_RECV_BUFFER_LEN: usize = 2048;

#[cfg(all(feature = "transport-api", target_family = "unix"))]
use libc::{self, c_int};

#[cfg(feature = "transport-api")]
use crate::api::{Caps, Class, ReceivedFrame, RecvMeta, SendMeta, Transport, TransportEvent, TransportResult};

#[cfg(feature = "transport-api")]
use crate::metrics::Metrics;

#[cfg(feature = "transport-api")]
use crate::wire::{self, parse_packet, ServiceClass};

#[cfg(feature = "transport-api")]
use crate::io::{pmtu::PmtuState, txtime::enable_txtime, txtime::GuardDeltaController, uring, xdp};

#[cfg(all(feature = "transport-api", target_os = "linux"))]
use nix::errno::Errno;
#[cfg(all(feature = "transport-api", target_os = "linux"))]
use nix::sys::socket::{
    self as nix_socket, recvmmsg, recvmsg, sendmmsg, setsockopt, sockopt, ControlMessage,
    ControlMessageOwned, MsgFlags, MultiHeaders, SockaddrIn, SockaddrIn6, SockaddrStorage,
};
#[cfg(all(feature = "transport-api", target_os = "linux"))]
use std::io::IoSliceMut;

#[cfg(all(feature = "transport-api", target_os = "linux"))]
const LINUX_BATCH_CAP: usize = 16;

#[cfg(all(feature = "transport-api", target_os = "linux"))]
struct LinuxState {
    recv_storage: Vec<Vec<u8>>,
    send_headers_v4: Option<MultiHeaders<SockaddrIn>>,
    send_headers_v6: Option<MultiHeaders<SockaddrIn6>>,
    recv_headers_v4: Option<MultiHeaders<SockaddrIn>>,
    recv_headers_v6: Option<MultiHeaders<SockaddrIn6>>,
    send_addrs_v4: Vec<Option<SockaddrIn>>,
    send_addrs_v6: Vec<Option<SockaddrIn6>>,
}

#[cfg(all(feature = "transport-api", target_os = "linux"))]
impl LinuxState {
    fn new(remote: &SocketAddr, buffer_len: usize) -> Self {
        let recv_storage = (0..LINUX_BATCH_CAP)
            .map(|_| vec![0u8; buffer_len])
            .collect();

        let send_headers_v4 = if remote.is_ipv4() {
            Some(MultiHeaders::<SockaddrIn>::preallocate(LINUX_BATCH_CAP, None))
        } else {
            None
        };
        let send_headers_v6 = if remote.is_ipv6() {
            Some(MultiHeaders::<SockaddrIn6>::preallocate(LINUX_BATCH_CAP, None))
        } else {
            None
        };

        let recv_headers_v4 = if remote.is_ipv4() {
            Some(MultiHeaders::<SockaddrIn>::preallocate(
                LINUX_BATCH_CAP,
                Some(nix::cmsg_space!([u8; 64])),
            ))
        } else {
            None
        };
        let recv_headers_v6 = if remote.is_ipv6() {
            Some(MultiHeaders::<SockaddrIn6>::preallocate(
                LINUX_BATCH_CAP,
                Some(nix::cmsg_space!([u8; 64])),
            ))
        } else {
            None
        };

        let send_addrs_v4 = vec![None; LINUX_BATCH_CAP];
        let send_addrs_v6 = vec![None; LINUX_BATCH_CAP];

        Self {
            recv_storage,
            send_headers_v4,
            send_headers_v6,
            recv_headers_v4,
            recv_headers_v6,
            send_addrs_v4,
            send_addrs_v6,
        }
    }
}

#[cfg(feature = "transport-api")]
#[derive(Debug, Clone, Copy)]
struct SocketProbedCaps {
    ecn: bool,
    gso: bool,
}

#[cfg(feature = "transport-api")]
impl SocketProbedCaps {
    fn without_support() -> Self {
        Self { ecn: false, gso: false }
    }
}

#[cfg(feature = "transport-api")]
#[derive(Debug, Clone)]
struct PendingFrame {
    meta: SendMeta,
    payload: Bytes,
}

#[cfg(feature = "transport-api")]
impl PendingFrame {
    fn len(&self) -> usize {
        self.payload.len()
    }
}

#[cfg(all(feature = "transport-api", target_os = "linux"))]
fn map_nix_error(err: nix::Error) -> io::Error {
    match err.as_errno() {
        Some(errno) => io::Error::from_raw_os_error(errno as i32),
        None => io::Error::new(io::ErrorKind::Other, err),
    }
}

#[cfg(all(feature = "transport-api", target_os = "linux"))]
fn configure_socket(socket: &Socket, remote: &SocketAddr) -> io::Result<SocketProbedCaps> {
    use std::os::fd::RawFd;

    fn enable_bool_opt<O>(fd: RawFd, opt: O) -> io::Result<bool>
    where
        O: nix::sys::socket::SetSockOpt<bool>,
    {
        match setsockopt(fd, opt, &true) {
            Ok(()) => Ok(true),
            Err(err) => match err.as_errno() {
                Some(Errno::ENOPROTOOPT) | Some(Errno::EINVAL) => Ok(false),
                Some(errno) => Err(io::Error::from_raw_os_error(errno as i32)),
                None => Err(io::Error::new(io::ErrorKind::Other, err)),
            },
        }
    }

    fn enable_optional<O, V>(fd: RawFd, opt: O, value: V) -> io::Result<()> 
    where
        O: nix::sys::socket::SetSockOpt<V>,
        V: Copy,
    {
        match setsockopt(fd, opt, &value) {
            Ok(()) => Ok(()),
            Err(err) => match err.as_errno() {
                Some(Errno::ENOPROTOOPT) | Some(Errno::EINVAL) => Ok(()),
                _ => Err(map_nix_error(err)),
            },
        }
    }

    let fd = socket.as_raw_fd();
    let mut ecn_supported = false;

    if remote.is_ipv4() {
        ecn_supported = enable_bool_opt(fd, sockopt::IpRecvTos)?;
        let ect = wire::with_ecn(0, wire::EcnCodepoint::Ect0) as libc::c_int;
        enable_optional(fd, sockopt::IpTos, ect)?;
        enable_optional(fd, sockopt::IpRecvErr, true)?;
        enable_optional(fd, sockopt::IpMtuDiscover, nix_socket::IpMtuDiscover::Do)?;
    } else {
        ecn_supported = enable_bool_opt(fd, sockopt::Ipv6RecvTclass)?;
        let ect = wire::with_ecn(0, wire::EcnCodepoint::Ect0) as libc::c_int;
        enable_optional(fd, sockopt::Ipv6TClass, ect)?;
        enable_optional(fd, sockopt::Ipv6RecvErr, true)?;
        enable_optional(fd, sockopt::Ipv6MtuDiscover, nix_socket::Ipv6MtuDiscover::Do)?;
    }

    Ok(SocketProbedCaps {
        ecn: ecn_supported,
        gso: false,
    })
}

#[cfg(all(feature = "transport-api", not(target_os = "linux")))]
fn configure_socket(_socket: &Socket, _remote: &SocketAddr) -> io::Result<SocketProbedCaps> {
    Ok(SocketProbedCaps::without_support())
}

#[derive(Debug, Error)]
pub enum UdpError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[cfg(feature = "transport-api")]
    #[error("wire error: {0}")]
    Wire(#[from] wire::WireError),
}

#[cfg(feature = "transport-api")]
#[derive(Debug)]
pub struct UdpTransport {
    socket: Socket,
    remote: SocketAddr,
    recv_buf: Vec<u8>,
    recv_queue: VecDeque<ReceivedFrame>,
    pending: VecDeque<PendingFrame>,
    caps: Caps,
    metrics: Arc<Metrics>,
    guard_delta: GuardDeltaController,
    pmtu: PmtuState,
    tos_cache: Option<u8>,
    #[cfg(target_os = "linux")]
    linux: LinuxState,
}

#[cfg(feature = "transport-api")]
impl UdpTransport {
    pub fn connect<A: ToSocketAddrs>(local: A, remote: SocketAddr, metrics: Arc<Metrics>) -> Result<Self, UdpError> {
        let local_addr = local
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing local address"))?;

        let domain = Domain::for_address(local_addr);
        let socket = Socket::new(domain, Type::DGRAM.nonblocking(), Some(Protocol::UDP))?;
        socket.bind(&local_addr.into())?;
        socket.connect(&remote.into())?;

        let mut caps = Caps::default();
        caps.io_uring = matches!(uring::detect_support(), uring::IoUringSupport::Available);
        caps.af_xdp = matches!(xdp::detect_support(), xdp::XdpSupport::Available);

        let mut guard_delta = GuardDeltaController::new(200_000, 2_000_000, 500_000);
        caps.etf = enable_txtime(socket.as_raw_fd(), guard_delta.current()).is_ok();

        let probed = configure_socket(&socket, &remote)?;
        caps.ecn = probed.ecn;
        caps.gso = probed.gso;

        let pmtu = PmtuState::new(1200, 1024, 1500, Duration::from_secs(1));
        caps.pmtu = pmtu.current();
        metrics.pmtu_current.set(caps.pmtu as i64);
        metrics.guard_delta_ns
            .set(guard_delta.current().as_nanos() as i64);
        metrics.tx_late_drop_rate.observe(0.0);

        #[cfg(target_os = "linux")]
        let linux = LinuxState::new(&remote, DEFAULT_RECV_BUFFER_LEN);

        Ok(Self {
            socket,
            remote,
            recv_buf: vec![0u8; DEFAULT_RECV_BUFFER_LEN],
            recv_queue: VecDeque::new(),
            pending: VecDeque::new(),
            caps,
            metrics,
            guard_delta,
            pmtu,
            tos_cache: None,
            #[cfg(target_os = "linux")]
            linux,
        })
    }

    fn flush_pending(&mut self) -> Result<(), UdpError> {
        if self.pending.is_empty() {
            #[cfg(target_os = "linux")]
            {
                self.poll_error_queue()?;
            }
            return Ok(());
        }
        self.pmtu.probe_timed_out(Instant::now());

        #[cfg(target_os = "linux")]
        {
            let result = self.flush_pending_linux();
            result?;
            self.poll_error_queue()?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            return self.flush_pending_fallback();
        }
    }

    fn flush_pending_fallback(&mut self) -> Result<(), UdpError> {
        while let Some(frame) = self.pending.pop_front() {
            if !self.can_transmit_len(frame.len()) {
                continue;
            }
            self.apply_ecn(&frame.meta).map_err(UdpError::Io)?;
            match self.socket.send(frame.payload.as_ref()) {
                Ok(_) => {
                    self.on_send_success(&frame);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.pending.push_front(frame);
                    break;
                }
                Err(err) => {
                    if err.kind() == io::ErrorKind::Other
                        && err.raw_os_error() == Some(libc::EMSGSIZE)
                    {
                        let attempted = frame.len().min(u16::MAX as usize) as u16;
                        self.handle_emsgsize(attempted);
                        continue;
                    }
                    return Err(UdpError::Io(err));
                }
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn flush_pending_linux(&mut self) -> Result<(), UdpError> {
        let fd = self.socket.as_raw_fd();

        while let Some(first) = self.pending.front() {
            if !self.can_transmit_len(first.len()) {
                self.pending.pop_front();
                continue;
            }

            self.apply_ecn(&first.meta).map_err(UdpError::Io)?;

            let allow_batch = first.len() <= self.pmtu.current() as usize;
            let max_batch = if allow_batch { LINUX_BATCH_CAP } else { 1 };
            let first_ecn = first.meta.ecn_capable;

            let mut sent = 0usize;
            {
                let mut buffers: Vec<[IoSlice<'_>; 1]> = Vec::new();
                for frame in self.pending.iter().take(max_batch) {
                    if frame.meta.ecn_capable != first_ecn {
                        break;
                    }
                    if allow_batch && frame.len() > self.pmtu.current() as usize {
                        break;
                    }
                    buffers.push([IoSlice::new(frame.payload.as_ref())]);
                }

                if buffers.is_empty() {
                    break;
                }

                let control: [ControlMessage<'_>; 0] = [];

                let result = if self.remote.is_ipv4() {
                    let headers = self
                        .linux
                        .send_headers_v4
                        .as_mut()
                        .expect("IPv4 send headers missing");
                    let addrs = &self.linux.send_addrs_v4[..buffers.len()];
                    sendmmsg(
                        fd,
                        headers,
                        buffers.iter(),
                        addrs,
                        &control,
                        MsgFlags::MSG_DONTWAIT,
                    )
                } else {
                    let headers = self
                        .linux
                        .send_headers_v6
                        .as_mut()
                        .expect("IPv6 send headers missing");
                    let addrs = &self.linux.send_addrs_v6[..buffers.len()];
                    sendmmsg(
                        fd,
                        headers,
                        buffers.iter(),
                        addrs,
                        &control,
                        MsgFlags::MSG_DONTWAIT,
                    )
                };

                match result {
                    Ok(mut results) => {
                        while results.next().is_some() {
                            sent += 1;
                        }
                    }
                    Err(nix::Error::Errno(Errno::EAGAIN | Errno::EWOULDBLOCK)) => break,
                    Err(nix::Error::Errno(Errno::EMSGSIZE)) => {
                        if let Some(frame) = self.pending.pop_front() {
                            let attempted = frame.len().min(u16::MAX as usize) as u16;
                            self.handle_emsgsize(attempted);
                        }
                        continue;
                    }
                    Err(err) => return Err(UdpError::Io(map_nix_error(err))),
                }
            }

            if sent == 0 {
                break;
            }

            for _ in 0..sent {
                if let Some(frame) = self.pending.pop_front() {
                    self.on_send_success(&frame);
                }
            }
        }

        Ok(())
    }

    fn decode_frame(
        &self,
        buf: &[u8],
        ecn_ce: bool,
        received_at: Instant,
    ) -> Result<ReceivedFrame, UdpError> {
        let parts = parse_packet(buf)?;
        let class = match parts.header.class {
            ServiceClass::P0 => Class::P0,
            ServiceClass::P1 => Class::P1,
            ServiceClass::P2 => Class::P2,
            ServiceClass::P3 => Class::P3,
        };

        let payload = Bytes::copy_from_slice(buf);
        let meta = RecvMeta {
            class,
            stream: parts.header.stream,
            slot: parts.header.slot,
            seq: parts.header.seq,
            len: buf.len(),
            ecn_ce,
            received_at,
        };

        Ok(ReceivedFrame { meta, payload })
    }

    fn handle_emsgsize(&mut self, attempted: u16) {
        self.pmtu.note_blackhole(attempted);
        let current = self.pmtu.current();
        self.caps.pmtu = current;
        self.metrics.pmtu_current.set(current as i64);
        self.metrics.pmtu_probe_fail.inc();
    }

    fn can_transmit_len(&mut self, len: usize) -> bool {
        if len <= self.pmtu.current() as usize {
            return true;
        }
        let now = Instant::now();
        if let Some(probe) = self.pmtu.next_probe(now) {
            if len <= probe as usize {
                return true;
            }
        }
        let attempted = len.min(u16::MAX as usize) as u16;
        self.handle_emsgsize(attempted);
        false
    }

    fn apply_ecn(&mut self, meta: &SendMeta) -> io::Result<()> {
        if !self.caps.ecn {
            return Ok(());
        }
        let desired = if meta.ecn_capable {
            wire::with_ecn(0, wire::EcnCodepoint::Ect1)
        } else {
            wire::with_ecn(0, wire::EcnCodepoint::NotEct)
        };
        if self.tos_cache == Some(desired) {
            return Ok(());
        }
        if self.remote.is_ipv4() {
            self.socket.set_tos(i32::from(desired))?;
        } else {
            self.socket.set_ipv6_tclass(i32::from(desired))?;
        }
        self.tos_cache = Some(desired);
        Ok(())
    }

    fn on_send_success(&mut self, frame: &PendingFrame) {
        let len = frame.len();
        let prev = self.pmtu.current();
        let len_u16 = len.min(u16::MAX as usize) as u16;
        self.pmtu.confirm_probe(len_u16);
        let current = self.pmtu.current();
        if current != prev {
            self.metrics.pmtu_probe_success.inc();
            self.metrics.pmtu_current.set(current as i64);
        }
        self.caps.pmtu = current;
        self.adjust_guard_delta(false);
    }

    #[cfg(target_os = "linux")]
    fn adjust_guard_delta(&mut self, late_drop: bool) {
        if !self.caps.etf {
            return;
        }
        let delta = self.guard_delta.adjust(late_drop);
        self.metrics
            .guard_delta_ns
            .set(delta.as_nanos() as i64);
        if late_drop {
            self.metrics.tx_late_drop_rate.observe(1.0);
        } else {
            self.metrics.tx_late_drop_rate.observe(0.0);
        }
        if enable_txtime(self.socket.as_raw_fd(), delta).is_err() {
            self.caps.etf = false;
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn adjust_guard_delta(&mut self, late_drop: bool) {
        if late_drop {
            self.metrics.tx_late_drop_rate.observe(1.0);
        } else {
            self.metrics.tx_late_drop_rate.observe(0.0);
        }
        self.metrics
            .guard_delta_ns
            .set(self.guard_delta.current().as_nanos() as i64);
    }

    #[cfg(target_os = "linux")]
    fn handle_extended_err(&mut self, err: &libc::sock_extended_err) -> bool {
        match err.ee_origin as i32 {
            origin if origin == libc::SO_EE_ORIGIN_TXTIME => true,
            origin
                if origin == libc::SO_EE_ORIGIN_ICMP
                    || origin == libc::SO_EE_ORIGIN_ICMP6 =>
            {
                if err.ee_errno == libc::EMSGSIZE {
                    let mtu = (err.ee_info as u32).min(u16::MAX as u32) as u16;
                    if mtu > 0 {
                        self.pmtu.update_from_mtu(mtu);
                        let current = self.pmtu.current();
                        self.caps.pmtu = current;
                        self.metrics.pmtu_current.set(current as i64);
                        self.metrics.pmtu_probe_fail.inc();
                    }
                }
                false
            }
            _ => false,
        }
    }

    #[cfg(target_os = "linux")]
    fn poll_error_queue(&mut self) -> Result<(), UdpError> {
        use std::io::IoSliceMut;

        let fd = self.socket.as_raw_fd();
        let mut buf = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut cmsg_space =
            nix::cmsg_space!([libc::sock_extended_err; 1], libc::sockaddr_storage);

        loop {
            match recvmsg::<SockaddrStorage>(
                fd,
                &mut iov,
                Some(&mut cmsg_space),
                MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(msg) => {
                    if msg.cmsgs().next().is_none() {
                        break;
                    }
                    let mut late_drop = false;
                    for cmsg in msg.cmsgs() {
                        match cmsg {
                            ControlMessageOwned::Ipv4RecvErr(err, _) => {
                                if self.handle_extended_err(&err) {
                                    late_drop = true;
                                }
                            }
                            ControlMessageOwned::Ipv6RecvErr(err, _) => {
                                if self.handle_extended_err(&err) {
                                    late_drop = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    if late_drop {
                        self.adjust_guard_delta(true);
                    }
                }
                Err(nix::Error::Errno(Errno::EAGAIN | Errno::EWOULDBLOCK)) => break,
                Err(err) => return Err(UdpError::Io(map_nix_error(err))),
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn poll_error_queue(&mut self) -> Result<(), UdpError> {
        Ok(())
    }

    fn populate_recv_queue(&mut self) -> Result<(), UdpError> {
        if !self.recv_queue.is_empty() {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            return self.recv_batch_linux();
        }

        #[cfg(not(target_os = "linux"))]
        {
            if let Some(frame) = self.recv_single_fallback()? {
                self.recv_queue.push_back(frame);
            }
            Ok(())
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn recv_single_fallback(&mut self) -> Result<Option<ReceivedFrame>, UdpError> {
        match self.socket.recv(&mut self.recv_buf) {
            Ok(len) if len > 0 => {
                let frame = self.decode_frame(&self.recv_buf[..len], false, Instant::now())?;
                Ok(Some(frame))
            }
            Ok(_) => Ok(None),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(err) => Err(UdpError::Io(err)),
        }
    }

    #[cfg(target_os = "linux")]
    fn recv_batch_linux(&mut self) -> Result<(), UdpError> {
        let fd = self.socket.as_raw_fd();
        if self.remote.is_ipv4() {
            let result = {
                let mut slices: Vec<[IoSliceMut<'_>; 1]> = self
                    .linux
                    .recv_storage
                    .iter_mut()
                    .take(LINUX_BATCH_CAP)
                    .map(|buf| [IoSliceMut::new(buf.as_mut_slice())])
                    .collect();
                if slices.is_empty() {
                    return Ok(());
                }
                let headers = self
                    .linux
                    .recv_headers_v4
                    .as_mut()
                    .expect("IPv4 headers prepared");
                recvmmsg(
                    fd,
                    headers,
                    slices.iter_mut(),
                    MsgFlags::MSG_DONTWAIT,
                    None,
                )
            };

            match result {
                Ok(mut results) => {
                    let mut idx = 0usize;
                    while let Some(msg) = results.next() {
                        let len = msg.bytes;
                        if len == 0 {
                            idx += 1;
                            continue;
                        }

                        let ecn_ce = msg.cmsgs().any(|cmsg| match cmsg {
                            ControlMessageOwned::Ipv4Tos(tos) => {
                                matches!(wire::ecn_from_tos(tos), wire::EcnCodepoint::Ce)
                            }
                            _ => false,
                        });

                        let frame = self.decode_frame(
                            &self.linux.recv_storage[idx][..len],
                            ecn_ce,
                            Instant::now(),
                        )?;
                        self.recv_queue.push_back(frame);
                        idx += 1;
                    }
                }
                Err(nix::Error::Errno(Errno::EAGAIN | Errno::EWOULDBLOCK)) => {}
                Err(err) => return Err(UdpError::Io(map_nix_error(err))),
            }
        } else {
            let result = {
                let mut slices: Vec<[IoSliceMut<'_>; 1]> = self
                    .linux
                    .recv_storage
                    .iter_mut()
                    .take(LINUX_BATCH_CAP)
                    .map(|buf| [IoSliceMut::new(buf.as_mut_slice())])
                    .collect();
                if slices.is_empty() {
                    return Ok(());
                }
                let headers = self
                    .linux
                    .recv_headers_v6
                    .as_mut()
                    .expect("IPv6 headers prepared");
                recvmmsg(
                    fd,
                    headers,
                    slices.iter_mut(),
                    MsgFlags::MSG_DONTWAIT,
                    None,
                )
            };

            match result {
                Ok(mut results) => {
                    let mut idx = 0usize;
                    while let Some(msg) = results.next() {
                        let len = msg.bytes;
                        if len == 0 {
                            idx += 1;
                            continue;
                        }

                        let ecn_ce = msg.cmsgs().any(|cmsg| match cmsg {
                            ControlMessageOwned::Ipv6Tclass(tclass) => {
                                let cls = (tclass & 0xff) as u8;
                                matches!(wire::ecn_from_tclass(cls), wire::EcnCodepoint::Ce)
                            }
                            _ => false,
                        });

                        let frame = self.decode_frame(
                            &self.linux.recv_storage[idx][..len],
                            ecn_ce,
                            Instant::now(),
                        )?;
                        self.recv_queue.push_back(frame);
                        idx += 1;
                    }
                }
                Err(nix::Error::Errno(Errno::EAGAIN | Errno::EWOULDBLOCK)) => {}
                Err(err) => return Err(UdpError::Io(map_nix_error(err))),
            }
        }

        Ok(())
    }
}

#[cfg(feature = "transport-api")]
impl Transport for UdpTransport {
    type Error = UdpError;
    type Event = TransportEvent;
    type Snapshot = Caps;

    fn caps(&self) -> Caps {
        self.caps
    }

    fn send(&mut self, meta: SendMeta, payload: Bytes) -> TransportResult<(), Self::Error> {
        if !self.can_transmit_len(payload.len()) {
            return Ok(());
        }
        self.pending.push_back(PendingFrame { meta, payload });
        self.flush_pending()?;
        Ok(())
    }

    fn poll(&mut self) -> TransportResult<Option<Self::Event>, Self::Error> {
        self.flush_pending()?;
        self.populate_recv_queue()?;
        if let Some(frame) = self.recv_queue.pop_front() {
            return Ok(Some(TransportEvent::Received(frame)));
        }
        Ok(Some(TransportEvent::Idle))
    }

    fn ack(&mut self, _ack: crate::api::AckSet) -> TransportResult<(), Self::Error> {
        Ok(())
    }

    fn snapshot(&self) -> TransportResult<Self::Snapshot, Self::Error> {
        Ok(self.caps)
    }
}

