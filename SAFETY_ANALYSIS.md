# Safety and Failure-Resilience Analysis for AxiomNet

## system_overview

AxiomNet is a Layer 3 overlay network daemon (Rust) that provides cryptographically secured, decentralized routing using hyperbolic geometry. Core responsibilities include:

- **Stateful Session Management**: Noise Protocol handshakes and encrypted sessions stored in concurrent HashMap (DashMap), managing cryptographic state transitions between handshaking and established states
- **Concurrent Routing**: Multi-threaded UDP packet reception and TUN interface handling with shared routing tables protected by parking_lot mutexes and DashMap for peer/route lookups
- **External I/O Dependencies**: File system operations for identity key persistence, UDP network I/O for peer communication, TUN device I/O for packet forwarding
- **Long-running Tasks**: Background heartbeat broadcasts, infinite UDP receive loops, signal handling for graceful shutdown
- **Cryptographic Operations**: Key generation, Noise handshakes, per-packet encryption/decryption with nonce management

## failure_modes

### 1. **Unbounded Blocking on Network I/O**
- **Location**: `src/main.rs:336` - `self.udp_socket.recv_from(&mut udp_buf).await`
- **Issue**: No timeout on UDP recv; will block indefinitely if no packets arrive
- **Condition**: Network partition, peer loss, or idle network
- **Impact**: Main event loop stalls; node becomes unresponsive to shutdown signals, cannot process new peers or routes

### 2. **Unbounded Blocking on File I/O**
- **Location**: `src/crypto.rs:28` - `fs::read(path)?` and `src/crypto.rs:41` - `fs::write(path, &key_bytes)?`
- **Issue**: Synchronous file I/O in async context without timeout
- **Condition**: Slow disk, NFS mount stall, file system deadlock
- **Impact**: Node startup hangs indefinitely; cannot recover without kill -9

### 3. **Missing Directory Creation**
- **Location**: `src/crypto.rs:26-43` - `load_or_generate` function
- **Issue**: Attempts to write to `./config/identity.key` without ensuring directory exists
- **Condition**: First run or deleted config directory
- **Impact**: Panics on write, losing any in-memory state; no recovery path

### 4. **Non-Atomic Identity File Writes**
- **Location**: `src/crypto.rs:41` - `fs::write(path, &key_bytes)?`
- **Issue**: Direct write without atomic rename pattern
- **Condition**: Crash or kill during write operation
- **Impact**: Partial key file write → corrupted identity → node can never rejoin network with same identity; data integrity violated

### 5. **Unchecked Buffer Bounds in Protocol Parsing**
- **Location**: `src/protocol.rs:47-56` - `SwitchHeader::decode`
- **Issue**: Uses `get_u8()`, `get_u32()`, `get_u64()` without checking buffer length first
- **Condition**: Malformed packet with truncated header
- **Impact**: Panics on underflow, DoS attack vector; entire node crashes

### 6. **Session State Corruption via Race Condition**
- **Location**: `src/session.rs:44-64` - `process_incoming` taking mutable reference to HandshakeState
- **Issue**: No synchronization if multiple tasks call process_incoming on same session
- **Condition**: Concurrent packet arrivals for same session (realistic under load)
- **Impact**: Handshake state machine corrupts; cryptographic nonces desync; session becomes unusable; potential security vulnerability

### 7. **Lock Contention Without Timeout**
- **Location**: `src/router.rs:77,81` - `self.self_coords.lock()`
- **Issue**: parking_lot::Mutex used but no timeout configured (blocks indefinitely)
- **Condition**: Bug in heartbeat broadcast holds lock; routing lookup waits forever
- **Impact**: All routing operations stall; livelock if multiple threads wait on each other

### 8. **Unbounded Session Growth**
- **Location**: `src/main.rs:62` - `sessions: Arc<DashMap<u32, Session>>`
- **Issue**: Sessions added via `next_session_id()` but never removed; no TTL or eviction
- **Condition**: Long-running node; peer churn
- **Impact**: Memory exhaustion → OOM kill; no graceful degradation

### 9. **Task Spawn Without Join Handles**
- **Location**: `src/main.rs:291,340` - `tokio::spawn(async move { ... })`
- **Issue**: Spawned tasks not stored; cannot await or cancel on shutdown
- **Condition**: Shutdown signal received
- **Impact**: Tasks continue running → data races if they access freed state; unclean shutdown; potential send-after-close errors

### 10. **Error Swallowing in Background Tasks**
- **Location**: `src/main.rs:318` - `let _ = udp.send_to(&encoded, peer_entry.1.addr).await;`
- **Issue**: Heartbeat send errors silently ignored
- **Condition**: Peer unreachable or network issue
- **Impact**: No observability; operator cannot diagnose why peer isn't responding; silent failures accumulate

### 11. **Unwrap on Floating-Point Comparison**
- **Location**: `src/topology.rs:72` - `.unwrap_or(std::cmp::Ordering::Equal)`
- **Issue**: Uses unwrap_or but could panic if future code removes it
- **Condition**: NaN coordinates due to arithmetic overflow or bad input
- **Impact**: Panic in routing decision → packet drop → network partition

### 12. **Missing Validation on Coordinates**
- **Location**: `src/topology.rs:32-35` - Returns `f64::INFINITY` but caller may not check
- **Issue**: Hyperbolic distance can return INFINITY if denominator ≤ 0
- **Condition**: Peer sends r ≥ 1.0 (violates Poincaré disk constraint)
- **Impact**: Routing algorithm picks "closest" neighbor as INFINITY → packet forwarding fails → black hole

## impact_analysis

### 1. Unbounded Network I/O Blocking
- **Correctness**: Node cannot process control messages → routing table stale → misdirected packets
- **Safety**: Signal handlers blocked → cannot shut down cleanly → must kill -9 → in-memory sessions lost
- **Data Integrity**: If crash during stalled recv, any pending session state updates lost (no write-ahead log)

### 2. Unbounded File I/O Blocking
- **Correctness**: Startup never completes → node offline → network partition
- **Safety**: Manual intervention required; no watchdog or timeout
- **Data Integrity**: If timeout mechanism exists but not used, operator may kill process during key generation → identity.key partially written

### 3. Missing Directory Creation
- **Correctness**: Binary fails to start → manual mkdir required → poor UX
- **Safety**: No fallback; panics immediately
- **Data Integrity**: N/A (fails before state created)

### 4. Non-Atomic Identity File Writes
- **Correctness**: Restarted node loads corrupt key → generates new identity → IP address changes → breaks all routes to this node
- **Safety**: Lost identity = lost network presence; peers must re-bootstrap
- **Data Integrity**: Violated—partial writes observable; no checksum to detect corruption

### 5. Unchecked Protocol Buffer Bounds
- **Correctness**: Attacker sends 10-byte packet → node panics → network partition
- **Safety**: DoS via crafted packets; no rate limiting
- **Data Integrity**: N/A (panics before processing)

### 6. Session State Race Condition
- **Correctness**: Nonce reuse or out-of-order nonces → Noise protocol security violated → authentication bypass possible
- **Safety**: Silent failure; both sides may believe handshake succeeded but keys differ
- **Data Integrity**: Encrypted payloads become undecryptable → data loss

### 7. Lock Contention Without Timeout
- **Correctness**: Routing queries block → heartbeats delayed → peers mark node as dead → routes withdrawn
- **Safety**: Deadlock if task A locks router and waits for session, task B locks session and waits for router
- **Data Integrity**: If shutdown during deadlock, in-memory routing table not persisted (though currently not persisted anyway)

### 8. Unbounded Session Growth
- **Correctness**: Slow memory leak; after hours/days, OOM → OS kills process → abrupt shutdown
- **Safety**: No graceful degradation; cannot serve new connections once memory full
- **Data Integrity**: All sessions lost on OOM crash; no state persistence

### 9. Task Spawn Without Join Handles
- **Correctness**: Shutdown races with background tasks → packets sent after socket closed → broken pipe errors logged
- **Safety**: Cannot guarantee clean shutdown; leaked resources (file descriptors, timers)
- **Data Integrity**: If heartbeat task writes to router after router dropped, UAF (Rust prevents, but task continues uselessly)

### 10. Error Swallowing in Background Tasks
- **Correctness**: Peer unreachable but no alert → operator unaware → manual intervention delayed
- **Safety**: Silent failures mask systemic issues (e.g., firewall misconfiguration)
- **Data Integrity**: N/A (but observability critical for diagnosing integrity issues elsewhere)

### 11. Unwrap on Float Comparison
- **Correctness**: NaN coordinates (from bad math or malicious peer) → panic → routing fails
- **Safety**: Entire node crashes; no isolation
- **Data Integrity**: N/A (panics before state mutation)

### 12. Missing Coordinate Validation
- **Correctness**: Route calculation returns INFINITY → packet forwarded nowhere → silent drop
- **Safety**: Malicious peer can black-hole traffic by sending invalid coords
- **Data Integrity**: No bounds checking on incoming control messages → protocol violation undetected

## hardening_recommendations

### 1. Add Timeouts to Network I/O
```rust
// src/main.rs:336
use tokio::time::{timeout, Duration};

tokio::select! {
    result = async {
        loop {
            // Wrap recv_from in timeout
            match timeout(Duration::from_secs(30), self.udp_socket.recv_from(&mut udp_buf)).await {
                Ok(Ok((n, from))) => {
                    let buf = udp_buf[..n].to_vec();
                    // process packet
                }
                Ok(Err(e)) => {
                    tracing::error!("UDP recv error: {}", e);
                }
                Err(_) => {
                    tracing::trace!("UDP recv timeout, checking shutdown");
                    // Allow shutdown check every 30s
                }
            }
        }
    } => result,
    _ = shutdown => {
        tracing::info!("Shutting down...");
        Ok(())
    }
}
```

### 2. Use Async File I/O with Timeout
```rust
// src/crypto.rs:26-43
use tokio::fs;
use tokio::time::{timeout, Duration};

pub async fn load_or_generate<P: AsRef<Path>>(path: P) -> Result<Self> {
    let path = path.as_ref();
    
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        timeout(Duration::from_secs(10), fs::create_dir_all(parent))
            .await
            .context("Timeout creating config directory")??;
    }
    
    if timeout(Duration::from_secs(5), path.try_exists())
        .await
        .context("Timeout checking if key exists")??
    {
        let key_bytes = timeout(Duration::from_secs(10), fs::read(path))
            .await
            .context("Timeout reading key file")??;
        // ... existing parsing logic
    } else {
        // Generate new key
        let params: NoiseParams = NOISE_PARAMS.parse()?;
        let builder = Builder::new(params);
        let static_keypair = builder.generate_keypair()?;
        
        // Atomic write: write to temp file, then rename
        let temp_path = path.with_extension("tmp");
        let mut key_bytes = Vec::new();
        key_bytes.extend_from_slice(&static_keypair.private);
        key_bytes.extend_from_slice(&static_keypair.public);
        
        timeout(Duration::from_secs(10), fs::write(&temp_path, &key_bytes))
            .await
            .context("Timeout writing temp key file")??;
        
        timeout(Duration::from_secs(5), fs::rename(&temp_path, path))
            .await
            .context("Timeout renaming key file")??;
        
        Ok(Self { static_keypair })
    }
}
```

### 3. Add Checksum Validation for Identity Files
```rust
// Add to src/crypto.rs
use blake2::{Blake2s256, Digest};

fn verify_key_integrity(key_bytes: &[u8]) -> Result<()> {
    if key_bytes.len() != 64 {
        anyhow::bail!("Key file corrupted: expected 64 bytes, got {}", key_bytes.len());
    }
    // Could add additional checksum validation if stored with key
    Ok(())
}

// Use in load_or_generate after reading
verify_key_integrity(&key_bytes)?;
```

### 4. Add Buffer Bounds Checking in Protocol Parsing
```rust
// src/protocol.rs:47
pub fn decode(buf: &mut Bytes) -> Result<Self> {
    if buf.remaining() < 16 {
        anyhow::bail!("Packet too short: expected at least 16 bytes for header, got {}", buf.len());
    }
    
    let route_label = buf.get_u32();
    let vt = buf.get_u8();
    let version = (vt & 0xF0) >> 4;
    let packet_type = PacketType::from_u8(vt & 0x0F)
        .ok_or_else(|| anyhow::anyhow!("Invalid packet type: {}", vt & 0x0F))?;
    
    if buf.remaining() < 11 {
        anyhow::bail!("Packet truncated: missing receiver_index and counter");
    }
    
    // Continue with remaining fields...
}
```

### 5. Add Session State Synchronization
```rust
// src/session.rs - Wrap Session in Arc<Mutex<>> at call sites
// Or make process_incoming require &mut self and document single-threaded access

// In src/main.rs:
// Change sessions to store Arc<tokio::sync::Mutex<Session>>
sessions: Arc<DashMap<u32, Arc<tokio::sync::Mutex<Session>>>>,

// When processing:
if let Some(session) = self.sessions.get(&session_id) {
    let mut session_guard = timeout(Duration::from_secs(5), session.lock())
        .await
        .context("Timeout acquiring session lock")?;
    session_guard.process_incoming(packet)?;
}
```

### 6. Add Session TTL and Cleanup
```rust
// Add to Session struct:
pub last_activity: Arc<std::sync::atomic::AtomicU64>, // Unix timestamp

// Update on each operation:
self.last_activity.store(
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs(),
    Ordering::Relaxed
);

// Background cleanup task in main.rs:
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        sessions.retain(|_id, session| {
            let last = session.last_activity.load(Ordering::Relaxed);
            now - last < 300 // 5-minute TTL
        });
    }
});
```

### 7. Add Coordinate Validation
```rust
// src/control.rs:18-27
pub fn handle_control_packet(
    msg: &ControlMessage,
    sender_addr: std::net::SocketAddr,
    routing_table: &crate::router::RoutingTable,
) {
    match msg {
        ControlMessage::Heartbeat { peer_id, my_coords, my_load } => {
            // Validate coordinates before using
            if !my_coords.is_valid() {
                tracing::warn!(
                    "Received invalid coordinates from {}: r={}, theta={}",
                    sender_addr, my_coords.r, my_coords.theta
                );
                return;
            }
            
            routing_table.update_peer_coords(*peer_id, *my_coords);
            routing_table.update_peer_load(*peer_id, *my_load);
        }
    }
}
```

### 8. Graceful Shutdown with Join Handles
```rust
// src/main.rs:280
async fn run(&self) -> Result<()> {
    let mut task_handles = Vec::new();
    
    // Store heartbeat task handle
    let heartbeat_handle = tokio::spawn(/* ... */);
    task_handles.push(heartbeat_handle);
    
    // Main loop...
    
    // On shutdown:
    tracing::info!("Shutting down gracefully...");
    for handle in task_handles {
        handle.abort(); // Or send shutdown signal
        let _ = handle.await; // Ignore cancellation errors
    }
    
    Ok(())
}
```

### 9. Add Observability for Errors
```rust
// src/main.rs:318
for peer_entry in router.get_peers() {
    if let Err(e) = udp.send_to(&encoded, peer_entry.1.addr).await {
        tracing::warn!(
            peer_addr = %peer_entry.1.addr,
            error = %e,
            "Failed to send heartbeat"
        );
        // Could increment metric: heartbeat_send_failures.inc()
    }
}
```

### 10. Add Circuit Breaker for Repeated Failures
```rust
// New module: src/circuit_breaker.rs
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

pub struct CircuitBreaker {
    failures: AtomicU32,
    threshold: u32,
    last_failure: parking_lot::Mutex<Option<Instant>>,
    timeout: Duration,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, timeout: Duration) -> Self {
        Self {
            failures: AtomicU32::new(0),
            threshold,
            last_failure: parking_lot::Mutex::new(None),
            timeout,
        }
    }
    
    pub fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        *self.last_failure.lock() = None;
    }
    
    pub fn record_failure(&self) -> bool {
        let count = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        *self.last_failure.lock() = Some(Instant::now());
        count >= self.threshold
    }
    
    pub fn is_open(&self) -> bool {
        if let Some(last) = *self.last_failure.lock() {
            if last.elapsed() < self.timeout {
                return self.failures.load(Ordering::Relaxed) >= self.threshold;
            }
        }
        false
    }
}
```

## recovery_readiness

### Invariants That Must Hold on Restart
1. **Identity Persistence**: Node must load same keypair to maintain IP address and peer trust
2. **No Partial Cryptographic State**: Sessions cannot be resumed across restarts (Noise protocol does not support)
3. **Routing Table Bootstrap**: Must rediscover peers via heartbeat gossip (no persistent routing state currently)

### State That Could Be Inconsistent After Crash
1. **Identity File**: May be partially written if crash during `fs::write` → CRITICAL
2. **In-Flight Sessions**: Peer may still have session open but local side lost state → peer must timeout
3. **Routing Entries**: All routes lost; peers still sending packets until they timeout

### Current Logging and Metrics
- **Logs**: tracing framework with debug/info/warn/error levels
- **Metrics**: NONE currently implemented
- **Diagnostic Info**: Packet counts, peer addresses logged but not aggregated
- **Crash Diagnostics**: No panic hook to log state; no coredumps configured

### Ratings (1–5 scale, 5 = best)

| Criterion | Rating | Rationale |
|-----------|--------|-----------|
| **Fault Tolerance** | 2 | Some use of Result for error handling, but no timeouts, no retry logic, no graceful degradation, single point of failure on file I/O |
| **Observability** | 2 | Logs exist but errors swallowed in key paths; no metrics; no health check; cannot diagnose why node is unresponsive |
| **Restart Safety** | 1 | Non-atomic key writes = potential corruption; no state validation on load; sessions not persisted; no checkpoints; network state must be fully reconstructed |

## test_plan_for_lock_and_failure

### Unit Tests
- [ ] `test_session_concurrent_process`: Spawn 100 threads calling `process_incoming` on same session; verify no panics, no nonce reuse
- [ ] `test_coordinate_validation`: Send coordinates with r=1.5, r=-0.1, theta=999 → verify rejected
- [ ] `test_protocol_decode_truncated`: Send 5-byte packet → verify returns Err, does not panic
- [ ] `test_session_cleanup_ttl`: Add 1000 sessions, simulate time passing, verify old sessions removed
- [ ] `test_circuit_breaker_opens`: Record 5 failures → verify is_open() returns true
- [ ] `test_hyperbolic_distance_infinity`: Create coords with r=1.0 → verify returns Err or handled gracefully

### Integration Tests
- [ ] `test_udp_timeout_allows_shutdown`: Start node, send no packets, send SIGTERM within 5s → verify clean exit
- [ ] `test_file_io_timeout_on_slow_disk`: Use FUSE fs with 20s delay, start node → verify fails with timeout error (not hang)
- [ ] `test_identity_recovery_from_corruption`: Write random bytes to identity.key, restart node → verify detects corruption, generates new key
- [ ] `test_atomic_identity_write`: Kill node during key generation 1000 times → verify key always valid or missing (never partial)
- [ ] `test_graceful_shutdown_stops_heartbeat`: Start node, send SIGTERM → verify heartbeat task terminates before process exit

### Property-Based Tests (using proptest)
- [ ] `prop_coordinate_distance_commutative`: For all valid coords c1, c2: distance(c1, c2) == distance(c2, c1)
- [ ] `prop_protocol_roundtrip`: For all valid packets: decode(encode(packet)) == packet
- [ ] `prop_session_counter_monotonic`: For all sequences of encryptions: counters are strictly increasing

### Chaos / Fault-Injection Scenarios
- [ ] **Kill Process During Key Write**: Script that starts node, waits 100ms, sends SIGKILL; repeat 100 times; verify key always loadable
- [ ] **Inject Network Partition**: Use `iptables` to drop packets to peer; verify node detects timeout, logs error, continues operating
- [ ] **Simulate Lock Contention**: Spawn 1000 tasks all trying to update routing table simultaneously; verify no deadlock, all complete within 10s
- [ ] **Exhaust File Descriptors**: Set ulimit low, start node with 100 peers; verify graceful error handling, no panic
- [ ] **Fill Disk During Key Write**: Mount tmpfs with 1KB space, try to write key; verify returns error, does not corrupt
- [ ] **Send Malformed Packets**: Fuzz test with 10,000 random byte sequences → verify no panics
- [ ] **Memory Pressure**: Run node under memory limit (valgrind, cgroups); verify OOM handling or backpressure

## summary_for_author

**High-Risk Items (Fix Immediately)**

1. **Non-Atomic Identity Key Writes**: Use atomic write-rename pattern in `crypto.rs:41` to prevent corruption on crash. Add checksum validation on load.

2. **Unbounded Network Blocking**: Wrap `recv_from` in `timeout()` in `main.rs:336` (30s timeout) to allow shutdown signal checking and prevent indefinite hangs.

3. **Missing Protocol Bounds Checking**: Add length validation in `protocol.rs:47` before calling `get_u*()` to prevent panic-based DoS attacks.

4. **Session State Race Condition**: Wrap `Session` in `tokio::sync::Mutex` or document that `process_incoming` must only be called from one task; current code is unsound under concurrent access.

5. **Coordinate Validation**: Add `is_valid()` check in `control.rs:19` before storing peer coordinates to prevent INFINITY distances causing routing failures.

**Medium-Risk Items (Address Soon)**

6. **Unbounded Session Growth**: Implement TTL-based cleanup (300s idle timeout) with background task to prevent memory exhaustion.

7. **Missing Directory Creation**: Add `fs::create_dir_all` in `crypto.rs:26` before writing identity.key to handle first-run gracefully.

8. **Error Swallowing**: Log all errors in heartbeat task (`main.rs:318`) with peer address and error context; consider adding metrics.

9. **Graceful Shutdown**: Store task JoinHandles and await/abort them in shutdown path to prevent resource leaks and data races.

10. **Lock Timeout**: Configure parking_lot Mutex with timeout (via try_lock + retry loop) or switch to tokio::sync::Mutex with timeout support.

**Immediate Actionable Steps**

1. Run `cargo test` to establish baseline (currently failing; fix compilation first)
2. Add unit test for `SwitchHeader::decode` with 5-byte input → must return Err
3. Implement atomic key write today (15 min fix, high impact)
4. Add timeout to main UDP recv loop (5 min fix, enables clean shutdown)
5. Add coordinate bounds checking (10 min fix, prevents routing black holes)
6. Create GitHub issue for comprehensive chaos testing framework (longer-term infrastructure)
7. Set up tracing pipeline to export metrics (e.g., OpenTelemetry) for production observability
