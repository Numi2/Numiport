Numiport:  Transport for Solana Validators


Numiport is a validator‑to‑validator transport specialized for Solana’s internal network paths. It replaces general‑purpose congestion control and connection‑level stream multiplexing with slot‑synchronous scheduling, single‑datagram work units, and topology‑aware behavior. The design uses continuous per‑slot byte credits with phase desynchronization, earliest‑deadline‑first (EDF) plus deficit round robin (DRR) arbitration, ECN‑guided next‑slot scaling, and kernel/NIC transmit‑time scheduling where available. Security is built around zero‑RTT PSKs for known peers and one‑RTT Noise IKpsk2 for unknown peers; records are protected with AEAD (XChaCha20‑Poly1305 by default) using session‑salted, direction‑scoped nonces and a pre‑AEAD header MAC for cheap rejection. Numiport is robust to MTU variance via dPLPMTUD and avoids IP fragmentation. It integrates tightly with Turbine’s randomized tree and repair logic, preserves stake‑weighted QoS while guaranteeing floors for repair and votes, and degrades cleanly on commodity kernels without ETF or AF_XDP. 

⸻

Solana’s validators disseminate shreds, votes, and repair traffic under strict slot deadlines. Common transports such as QUIC optimize for fairness across heterogeneous Internet paths using RTT‑driven probing, per‑connection stream machinery, and general congestion control. Those features cost cycles and inject jitter that do not align with slot‑bounded, topology‑aware dissemination on a trusted validator mesh.

Numiport specializes to this environment. The core idea is to bind all transport decisions to the slot clock and to move from fairness‑oriented control to deterministic per‑slot budgets with explicit priorities. Shreds and votes travel as independent datagrams, eliminating cross‑flow head‑of‑line blocking. Pacing is computed from slot budgets and, when available, delegated to the NIC using transmit‑time scheduling to minimize jitter.

i detail the architecture and wire format, define the scheduling and flow control model, and explain the security and MTU mechanisms that make the system safe at scale. uses per‑peer actors, clear module boundaries, and feature‑gated IO backends.

⸻

System model and assumptions

Network. Validators form a partial mesh with randomized Turbine overlays. Links range from intra‑DC low‑latency paths to cross‑DC WAN paths with higher delay and loss. Class‑of‑service differentiation may or may not exist in the underlay.

Timing. Slots are configured near 400 ms and may extend toward 600 ms. Transport‑level deadlines are keyed to observed slot length Δslot.

Trust. Validator identities are known; peers are authenticated either via pre‑shared keys (PSKs) or Noise handshakes. We assume honest‑but‑lossy network behavior from most peers, with a minority of adversarial or misconfigured nodes.

Work units. Each logical unit (shred, vote, repair, control) is delivered in exactly one UDP datagram. There are no multiplexed streams.

Adversary. Can inject, reorder, drop, replay, reflect, or ECN‑mark packets; can attempt CPU and bandwidth amplification; can exploit MTU blackholes; can try nonce reuse via restarts. Cannot break standard cryptography.

⸻

Design overview
	•	Slot‑synchronous scheduling. Credits are measured in bytes per slot and refilled continuously (leaky‑bucket). EDF enforces deadlines; DRR shares capacity between P1 shreds and P2 repair with explicit floors. P0 votes have strict priority with burst caps to prevent starvation of repair.
	•	Phase desynchronization. A per‑peer phase offset avoids synchronized slot‑edge microbursts.
	•	ECN‑guided scaling. Numiport reads ECN marks, aggregates per‑slot CE ratios, and deterministically scales next‑slot credits within bounds without RTT loops.
	•	Pacing. Transmit‑time is specified per packet. With SO_TXTIME + ETF, the qdisc or NIC launches frames at scheduled times. Without ETF, a software pacer approximates the schedule.
	•	Security. Authentication is PSK‑based for known peers or Noise IKpsk2 for unknown. A pre‑AEAD header MAC cheaply rejects junk before decryption. Record protection uses AEAD with session‑salted, direction‑scoped nonces; replay windows span multiple slots.
	•	MTU. Datagram PLPMTUD probes discover the path MTU. UDP GSO segments comply with discovered PMTU. IP fragmentation is disabled.
	•	Topology integration. Neighbor sets are cached with tight TTLs and diversity guards. Turbine’s randomized mapping remains authoritative.
	•	Fallbacks. IO features (ETF, AF_XDP, io_uring, MSG_ZEROCOPY) are probed and negotiated. Behavior degrades gracefully to UDP batching.

⸻

4. Related work and comparison

QUIC specifies connection‑oriented transport with TLS 1.3, RTT‑driven recovery, congestion control, and stream multiplexing. Those mechanisms are necessary for the open Internet. Numiport removes per‑connection fairness and RTT probing on trusted meshes; it replaces streams with single‑unit datagrams and substitutes ECN‑bounded, slot‑deterministic credit scaling for AIMD. Prior work on kernel transmit‑time scheduling and AF_XDP informs Numiport’s pacing and zero‑copy paths. Numiport borrows Noise patterns for compact, auditable handshakes.

⸻

5. Protocol specification

5.1 Packet format

All fields use network byte order. The fixed header is 32 bytes and is cache‑aligned.

struct NumiHdr {
  u8    ver;                // 1
  u8    cls:2, flags:6;     // 0=P0,1=P1,2=P2,3=P3; see below
  u64   slot;               // absolute slot
  u32   stream;             // 0=shred,1=vote,2=repair,3=ctrl
  u32   seq;                // per-(peer,slot,stream) increasing
  u16   fec_total;          // 0 if none; count of data+coding in group
  u16   shred_idx;          // 0 if none; index within FEC group
  u16   plen;               // payload bytes (excl tag)
  u16   rsvd;               // must be zero; aligns to 32B
}

Flags. ACK_ONLY, NACK, FEC, PSK_ID, CTRL, ECN_SUMMARY.

TLVs. Each TLV is (type: u8, len: u16, value[len]), padded to 4 bytes.
	•	CAPS { u32 bitmap, u16 pmtu, u8 ecn }
	•	PSK_ID { u32 psk_id }
	•	ACK_RLE { (u16 start, u16 run_len)* }
	•	NACK_LIST { (u32 seq)* } (bounded length)
	•	PMTU { u16 current_mtu }
	•	ECN_SUMMARY { u16 ce_ratio_milli }
	•	RETRY_COOKIE { opaque ≤ 32B }
	•	HDR_MAC { HMAC‑SHA256[0..16] }
	•	END {}

Payload protection. When encryption is active, TLVs and payload are covered by AEAD with tag appended. The AAD is the fixed header and all TLVs except HDR_MAC and RETRY_COOKIE.

Header MAC. HMAC‑SHA256 truncated to 16 bytes over fixed header + TLVs (excluding HDR_MAC and RETRY_COOKIE). Verified before attempting AEAD.

5.2 Classes and QoS
	•	P0 (votes, leader‑critical control): strict priority with a small burst cap.
	•	P1 (shreds): high throughput, ECN‑capable.
	•	P2 (repair): reserved floor and DRR sharing with P1.
	•	P3 (background): best effort.

IP TOS: DSCP per class where permitted. ECN: set ECT(1) on P1/P2.

5.3 Acknowledgments and reliability
	•	ACK cadence: send ACK_RLE every 16 packets or 5 ms, whichever first, and piggyback on outgoing packets.
	•	ACK windowing: maintained per (peer, slot, stream).
	•	NACK policy: allowed only for P0/P1 within the last 10 ms of the slot; bounded list length.
	•	Duplicates: per‑peer sliding replay window spanning W slots (default 4).
	•	Retransmit policy: no in‑slot retransmit for P1; rely on Turbine+FEC. Single fast resend for P0 if ACK missing by min(Δslot/8, 20 ms).

5.4 Flow control and scheduling

Let Δslot be the observed slot length.
	•	Credits. For class c, bytes per slot B_c translate to a continuous refill rate rate_c = B_c / Δslot. Credits accrue in a leaky‑bucket and cap at B_c.
	•	Phase desync. Each peer draws a deterministic phase ϕ ∈ [0, Q) with Q = Δslot / N, where N is the nominal number of bursts; this staggers dequeues at slot start.
	•	Arbitration.
	•	P0 strict priority with burst cap M0.
	•	P1 and P2 share via DRR with quantum values q1, q2 and a floor for P2 (floor_P2).
	•	P3 dequeued only when higher classes are idle.
	•	Deadlines. EDF within each class, with deadline = slot_end − margin_c. Margins widen under cross‑DC profile.
	•	ECN scaling. Aggregate CE ratio per peer for last slot. Next slot, scale credits:

s = { 0.70 if CE ≥ 2.0%
    , 0.85 if CE ≥ 1.0%
    , 0.98 if CE < 0.2% for 16 consecutive slots
    , 1.00 otherwise }
B_c' = clamp(s · B_c, [B_min, B_max])

Changes per slot are bounded to preserve determinism.

	•	Burst clamps. After M1 contiguous P1 dequeues, yield one scheduling opportunity to P2 if P2 has backlog.

5.5 Pacing and transmit time
	•	ETF path. If SO_TXTIME + ETF is available, compute tx_time = now + offset(seq, ϕ) and set SCM_TXTIME. Use CLOCK_TAI. Late packets are dropped by strict‑mode ETF and reported via error queue.
	•	Guard delta auto‑tune. Maintain target late‑drop rate ≤ 0.1%. Increase/decrease guard delta in 50 µs steps within [200 µs, 2 ms] to meet target.
	•	Fallback path. Without ETF, a software pacer enforces tx_time ordering using high‑resolution timers.

5.6 Slot‑clock synchronization

A timebase servo maintains a linear map t = a·slot + b to CLOCK_TAI using observed leader beacons. The servo tracks uncertainty; when uncertainty is high, margins and guard deltas widen automatically. The scheduler reads Δslot from the servo at each slot boundary.

5.7 Topology integration

Neighbor sets for Turbine are precomputed and cached with TTL of 2–4 slots plus jitter, then refreshed. A diversity guard ensures a minimum number of distinct upstream parents over a sliding window to improve resilience against targeted loss. Elevated loss or CE on a branch triggers early neighbor refresh.

5.8 Cryptography and identity
	•	Handshake.
	•	PSK zero‑RTT for known peers using a PSK_ID TLV.
	•	Noise IKpsk2 one‑RTT for unknown peers; sessions are cached per epoch.
	•	Record protection. AEAD XChaCha20‑Poly1305 by default. Operators may enable AES‑GCM‑SIV for P0 at build time.
	•	Nonces. For each direction and peer, derive a session salt salt = HKDF(master, "nonce-salt" || session_id || peer_ids || epoch). Nonce = first 24 bytes of BLAKE3(salt, slot || stream || seq || direction). Persist session_id to avoid reuse across restarts.
	•	Header MAC. HMAC‑SHA256 truncated to 16 bytes; keyed from the same master via HKDF. Verified before AEAD to reject junk cheaply.
	•	Retry + amplification. For unknown or failing peers, send stateless RETRY_COOKIE and require echo. Pre‑auth amplification is bounded to 3× bytes‑in over ~1 RTT.
	•	Key rotation. Accept current and next epoch PSKs for a grace window; advertise supported PSK_IDs in CAPS.

⸻

6. Kernel and NIC integration

6.1 UDP batching

Use sendmmsg/recvmmsg to batch I/O. Enable UDP GSO for segmentation; on receive, leverage GRO to coalesce. Set IP_PMTUDISC_DO and treat EMSGSIZE as a PMTU signal to avoid IP fragmentation.

6.2 Pacing with SO_TXTIME + ETF

Install the ETF qdisc: clockid=CLOCK_TAI, strict mode, initial guard delta 500 µs, offload enabled when the NIC supports LaunchTime. The error queue is polled to measure late‑drop events and kernel‑reported PMTU changes.

6.3 io_uring and MSG_ZEROCOPY

An io_uring backend can reduce syscall overhead; where supported, MSG_ZEROCOPY reduces copy cost. Both are optional and negotiated.

6.4 AF_XDP

AF_XDP provides a zero‑copy path for supported NICs/drivers with UMEM rings. Numiport falls back to copy mode or regular UDP automatically when zero‑copy is unavailable.

6.5 ECN capture

Enable IP_RECVTOS/IPV6_RECVTCLASS to read ECN bits on receive. Aggregate CE marks per slot and advertise summary via ECN_SUMMARY TLV.

⸻

7. MTU robustness: Datagram PLPMTUD

Numiport maintains a per‑peer PMTU cache. It starts conservatively (e.g., 1200 bytes payload) and probes larger sizes with DF set. Probes follow an exponential or binary search up to a configured cap; blackholed sizes are avoided for a backoff interval. UDP GSO segment size is clamped to PMTU − headers. A PMTU TLV accelerates convergence after restarts.

⸻

8. Security analysis

Nonce reuse. Catastrophic if unmitigated. Session‑salted, direction‑scoped nonces with persisted session IDs prevent reuse across restarts. Property tests enforce uniqueness across (slot, stream, seq, direction).

Handshake CPU DoS. Header MAC and stateless retry cookies cheaply reject unauthenticated junk. IKpsk2 is attempted only after cookie validation. Pre‑auth amplification is capped at 3×.

Replay. Per‑peer sliding replay windows spanning multiple slots discard duplicates. Window size balances tolerance for reordering against memory.

Topology attacks. Diversity guard and short neighbor TTLs reduce ossification and targeted path bias.

Fairness and starvation. P0 strict priority is bounded by burst caps; P2 repair has explicit floors. Stake‑weighted caps coexist with floors to protect small validators from starvation.

MTU blackholes. dPLPMTUD prevents reliance on IP fragmentation and quickly adapts to path changes.

Header integrity. CRC16 is removed; a keyed header MAC prevents CPU burn from malformed headers before decryption.

⸻

9. Performance model

Let per‑class budget be B_c bytes per slot. Continuous refill rate is rate_c = B_c / Δslot. Assume S shreds per slot, each size σ. Pacing quantum is Q = Δslot / N for nominal bursts N. Under ETF, jitter is bounded by guard delta and NIC scheduling variance; without ETF, software pacing adds timer granularity jitter.

Targets (intra‑DC).
	•	P1 shreds: p50 < 10 ms, p99 < 40 ms.
	•	P0 votes: p99 < 5 ms.
	•	CPU: ≤0.8× cycles of user‑space QUIC for equal throughput.

Cross‑DC profile. Margins widen; P1 p99 < 70 ms at 1–3% loss with ECN scaling active.

⸻

10. Implementation in Rust

10.1 Architecture

Use an async runtime (Tokio). Each remote validator is handled by a peer actor that owns:
	•	send/recv queues partitioned by class, with EDF within each class;
	•	credit buckets and DRR state;
	•	per‑peer crypto context (PSK or Noise session), header‑MAC keys, session ID;
	•	per‑peer PMTU and ECN statistics;
	•	IO backend handle (UDP + GSO, io_uring, or AF_XDP);
	•	replay window and ACK state;
	•	metrics counters and a debug snapshot.

A node‑wide clock task maintains the slot↔TAI map and publishes Δslot and margins.

10.2 Modules and responsibilities

numiport/
  src/
    api.rs          // public Transport trait and types
    wire.rs         // header/TLV parsing, network byte order, padding
    ack.rs          // RLE ACKs and replay window
    crypto/
      psk.rs        // PSK store and rotation with overlap
      noise.rs      // Noise IKpsk2 handshake via 'snow'
      aead.rs       // XChaCha20-Poly1305, optional AES-GCM-SIV
      hmac.rs       // header MAC (HMAC-SHA256 truncated)
      nonce.rs      // session-salted nonce derivation
    sched/
      credits.rs    // leaky-bucket credits, ECN scaling
      drr.rs        // DRR with floors and quantum
      edf.rs        // EDF queue with deadlines
      phase.rs      // per-peer phase desync
    io/
      udp.rs        // sendmmsg/recvmmsg, UDP_SEGMENT, ECN read
      uring.rs      // io_uring backend, MSG_ZEROCOPY
      xdp.rs        // AF_XDP backend
      txtime.rs     // SO_TXTIME + ETF helpers and error-queue reader
      pmtu.rs       // dPLPMTUD state machine
    topo.rs         // neighbor TTLs and diversity guard
    repair.rs       // repair request/serve helpers
    metrics.rs      // Prometheus and tracing
    config.rs       // tunables and profiles (intra-DC, cross-DC)
    peer.rs         // per-peer actor task
    clock.rs        // slot↔TAI servo

10.3 Public API

#[derive(Copy, Clone, Debug)]
pub enum Class { P0, P1, P2, P3 }

#[derive(Copy, Clone, Debug)]
pub struct SendMeta {
    pub class: Class,
    pub stream: u32,
    pub slot: u64,
    pub seq: u32,
    pub ecn_capable: bool,
}

#[derive(Copy, Clone, Debug)]
pub struct Caps {
    pub etf: bool, pub gso: bool, pub af_xdp: bool, pub io_uring: bool,
    pub pmtu: u16, pub ecn: bool
}

pub trait Transport {
    fn send(&self, peer: PeerId, meta: SendMeta, payload: &[u8]) -> anyhow::Result<()>;
    fn poll(&self, max_pkts: usize) -> Vec<(PeerId, NumiHdr, bytes::Bytes)>;
    fn ack(&self, peer: PeerId, slot: u64, stream: u32, ack: AckSummary);
    fn caps(&self, peer: PeerId) -> Caps;
    fn snapshot(&self, peer: PeerId) -> DebugSnapshot;
}

10.4 Wire parsing checklist
	•	Enforce total packet size bounds before allocations.
	•	Parse fixed header, then TLVs with strict length checking and 4‑byte padding.
	•	If a shared secret exists, verify HDR_MAC before AEAD. On failure, drop and count.
	•	Construct AAD over fixed header + TLVs (minus HDR_MAC and RETRY_COOKIE).
	•	Verify AEAD tag; on failure, drop and count.
	•	Maintain replay window keyed by (slot, stream, seq).

10.5 Scheduler outline
	•	Credits: accrues using last_refill and rate_per_ns; clamped to B_c.
	•	EDF: min‑heap keyed by deadline; per class.
	•	DRR: deficits deficit_p1, deficit_p2 accumulate by quanta; select flows while deficits ≥ packet size.
	•	Burst caps: counters reset on class switch.
	•	Phase: per‑peer phase in nanoseconds applied to first‑slot dequeues.
	•	ECN scale: applied at slot boundary; bounded rate of change.

10.6 Pacing
	•	With ETF, SCM_TXTIME per packet; error queue parsed for late‑drops via SO_EE_ORIGIN_TXTIME.
	•	Guard delta manager tunes to target late‑drop.
	•	Without ETF, use a wheel timer or high‑res sleep with deadline ordering; preserve order across packets to a peer.

10.7 Crypto
	•	PSK store accepts current and next epoch IDs; rotates on schedule; exposes an API to query accepted IDs.
	•	Noise IKpsk2 via snow; session cache keyed by (peer, epoch).
	•	Nonce derivation uses HKDF‑derived salts and BLAKE3 to map (slot, stream, seq, direction) into 24‑byte XChaCha nonces.
	•	Header‑MAC keys derived alongside AEAD keys.
	•	Retry cookies are HMACs over (src_ip || slot_window || nonce) with server secret; no per‑client state required.

10.8 dPLPMTUD
	•	Maintain cur, min, max PMTU; blacklist set for failed sizes.
	•	Probe path on timer or on EMSGSIZE; backoff on timeout.
	•	Segment GSO payloads to cur − overhead.

10.9 Observability

Prometheus metrics and tracing:
	•	Pacing: tx_late_drop_rate, guard delta, software pacing overruns.
	•	Congestion: ecn_ce_ratio, credit scales applied.
	•	MTU: pmtu_current, probe success/fail counts.
	•	Security: aead_fail_rate, hdr_mac_fail, retry_cookie_sent/ok.
	•	Reliability: ack_bytes_total, nack_count, dup_filter_hits.
	•	Scheduling: burst_clamps, floor_hits_p2, queue depths per class.

A debog RPC returns a per‑peer snapshot: negotiated CAPS, PMTU, current credits, ECN stats, replay window occupancy, feature flags in use.

⸻

11. eval plan

Correctness.
	•	Fuzz TLV and header parsing with malformed inputs.
	•	Property‑test nonce uniqueness across restarts and epochs.
	•	Validate Noise IKpsk2 against test vectors; simulate stateless retry paths.
	•	Verify replay windows: no false rejects within configured reordering depth.

Performance.
	•	Intra‑DC latency distributions for P0/P1 with ETF on/off; CPU cycles/packet vs UDP baseline and vs QUIC.
	•	Late‑drop rate convergence with guard delta auto‑tune.
	•	Throughput under synchronized slot starts; measure effect of phase desync.

Resilience.
	•	Loss injection 0–30% with tc netem; verify block completion with FEC and post‑slot repair.
	•	ECN marking at 1–5%; verify deterministic next‑slot scaling and stability.
	•	PMTU blackholes for specific sizes; verify clamp without IP fragmentation.
	•	DoS: flood untrusted traffic; ensure header‑MAC and retry cookies bound CPU and bytes via 3× rule.

WAN profile.
	•	Latency 20–40 ms, loss 1–3%. Confirm cross‑DC profile meets targets and floors preserve repair.

⸻

12. Operational guidance
	•	ETF install. tc qdisc replace dev $IFACE root etf clockid CLOCK_TAI delta 500000 strict offload.
	•	Kernel features. Enable UDP GSO/GRO; check NIC offloads with ethtool -k. Match RX/TX queue count to pinned cores.
	•	Caps negotiation. Log negotiated features per peer on startup; alert on downgrade from expected caps.
	•	Alarms.
	•	Rising aead_fail_rate → force retry‑cookie mode.
	•	Persistent high ecn_ce_ratio → clamp credits and raise operator alert.
	•	Increasing tx_late_drop_rate → guard delta grows; alert if pinned at max.
	•	Rotation. Roll PSKs with overlapping acceptance windows; monitor PSK_ID mismatches.

⸻

13. critiques
	•	No multi‑tenant fairness. The validator mesh is not a public multi‑tenant network. Stake‑weighted caps and class floors handle local contention. Public ingress stays on QUIC. Fairness is orthogonal to slot‑synchronous delivery.
	•	ETF availability. ETF is optional. Without LaunchTime offload the software pacer still enforces slot‑paced credits and EDF/DRR. Jitter rises but deadlines remain bounded by guard‑delta and scheduler policy. Operators can choose NICs with LaunchTime later.
	•	ECN deployment gaps. ECN only tunes next‑slot budgets. If ECN is stripped, Numiport runs with static credits and the same pacing. Determinism and slot alignment remain. You can enable a loss‑hint scaler per slot if you want extra adaptation without RTT loops.
	•	Conservative FEC. The main gains come from one‑datagram semantics, EDF/DRR, and pacing. Fixed RS parameters already match Turbine’s repair model. Adaptive coding is an incremental win, not a prerequisite.
	•	No transport multipath. Turbine already gives path diversity at the application layer. Single‑path transport does not remove that. Multipath at the transport can be added without redesigning the wire.
⸻

14. End 

Numiport aligns transport behavior with Solana’s slot timing and Turbine topology. It replaces general‑purpose congestion control with deterministic, ECN‑bounded per‑slot credits; eliminates stream‑level coupling; and leverages kernel/NIC transmit‑time scheduling for low jitter. Security is explicit and auditable, with compact handshakes, misuse‑resistant nonce discipline, and pre‑AEAD filtering. MTU robustness and topology freshness round out a system engineered for predictable propagation under load. 

⸻

recommended reading if u interested in this sort of stuff and want to get filled in
	•	R. Hamilton et al., “QUIC Loss Detection and Congestion Control,” RFC 9002.
	•	M. Thomson, S. Turner, “Using TLS to Secure QUIC,” RFC 9001.
	•	Linux kernel docs: ETF qdisc, SO_TXTIME, UDP GSO/GRO, AF_XDP.
	•	T. Perrin, “The Noise Protocol Framework.”
	•	XChaCha20‑Poly1305 (libsodium documentation and draft analyses).
	•	ECN (RFC 3168) and Datagram PLPMTUD (RFC 8899).
	•	Solana Turbine and stake‑weighted QoS design notes.

⸻

Appendix A: Normative requirements summary
	•	A sender MUST treat each work unit as one datagram and avoid IP fragmentation.
	•	A sender MUST maintain per‑class credits refilled continuously at rate_c = B_c / Δslot.
	•	A scheduler MUST apply strict priority to P0 with a bounded burst cap and MUST provide a floor to P2.
	•	A sender SHOULD set ECT(1) on P1/P2 and MUST read CE marks if available.
	•	Next‑slot credit scaling MUST be deterministic and bounded as specified.
	•	A TLV parser MUST enforce bounds and 4‑byte padding.
	•	If a shared secret exists, a receiver MUST verify HDR_MAC before attempting AEAD.
	•	Nonces MUST be session‑salted, direction‑scoped, and unique across (slot, stream, seq).
	•	Before authentication, amplification MUST NOT exceed 3× of bytes‑in over a nominal RTT.
	•	IP fragmentation MUST be disabled; PMTU MUST be discovered via dPLPMTUD.
	•	Replay windows MUST span at least 4 slots or the configured window W.
	•	Feature negotiation MUST fall back to the intersection of advertised CAPS.

⸻

Appendix B: Wire details

Header fields.
	•	ver: Protocol version. Set to 1.
	•	cls: Two bits. 0=P0, 1=P1, 2=P2, 3=P3.
	•	flags: Six bits; reserved bits MUST be zero.
	•	slot: Absolute slot, 64‑bit.
	•	stream: 0=shred, 1=vote, 2=repair, 3=ctrl; future streams require version bump or CAPS.
	•	seq: Monotonic per (peer, slot, stream); wrap invalidates the slot.
	•	fec_total, shred_idx: Optional FEC grouping for shreds.
	•	plen: Payload bytes excluding AEAD tag.

TLVs.
	•	ACK_RLE: Sorted, non‑overlapping ranges; total bytes bounded (implementation default 64 B).
	•	NACK_LIST: Max entries bounded (default 8) and only honored for P0/P1 near slot end.
	•	CAPS: Feature bitmask; includes flags for ETF, GSO, AF_XDP, io_uring, ECN, and pmtu hint.
	•	HDR_MAC: Omitted if no shared secret; required thereafter.

⸻

Appendix C: Scheduling parameters (defaults)
	•	Per‑peer credits on 10 GbE: B_P0=64 KB, B_P1=2 MB, B_P2=1 MB, B_P3=256 KB.
	•	Floors: floor_P0=64 KB, floor_P2=256 KB per slot per peer.
	•	Burst caps: M0=8 for P0, M1=8 for P1.
	•	DRR quanta: q1=64 KB, q2=64 KB.
	•	Guard delta: auto‑tune 200 µs–2 ms, initial 500 µs.
	•	ACK cadence: every 16 packets or 5 ms.
	•	Replay window W=4 slots.
	•	PMTU: start at 1200 B payload; probe every 60 s or on EMSGSIZE.

⸻

Appendix D: Rust developer checklist
	•	Implement wire.rs with strict bounds and 4‑byte TLV padding.
	•	Add HDR_MAC pre‑AEAD verification with truncated HMAC‑SHA256.
	•	Implement session‑salted nonce derivation and persist session_id.
	•	Build PSK store with overlapping acceptance; Noise IKpsk2 via snow.
	•	Implement leaky‑bucket credits + EDF + DRR with floors and burst caps.
	•	Implement ECN aggregation and deterministic next‑slot scaling.
	•	Implement dPLPMTUD and clamp UDP_SEGMENT.
	•	Implement SO_TXTIME + ETF; parse MSG_ERRQUEUE for late‑drops and PMTU.
	•	Add io_uring and AF_XDP backends behind features.
	•	Expose Prometheus metrics and a debug snapshot RPC.
	•	Create test harnesses for loss, ECN, PMTU, retry cookies, nonce crash‑recovery.
	•	Integrate neighbor TTL + diversity guard with Turbine.

⸻

Appendix E: Glossary
	•	Δslot: Observed slot length.
	•	EDF: Earliest Deadline First scheduling.
	•	DRR: Deficit Round Robin.
	•	ECN/CE: Explicit Congestion Notification / Congestion Experienced.
	•	ETF: Earliest TxTime First qdisc.
	•	GSO/GRO: Generic Segmentation/Receive Offload.
	•	dPLPMTUD: Datagram Path MTU Discovery.
	•	PSK: Pre‑Shared Key.
	•	AEAD: Authenticated Encryption with Associated Data.
	•	Noise IKpsk2: A one‑RTT Noise pattern with initiator static key and PSK.
	•	HDR_MAC: Header Message Authentication Code.
	•	TAI: International Atomic Time.
