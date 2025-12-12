# AxiomNet AI Coding Agent Instructions

## Project Overview
AxiomNet is a **Layer 3 overlay network daemon** (like Yggdrasil/cjdns) using hyperbolic routing in the Poincaré disk model. It establishes cryptographically-secure peer connections over UDP and provides a TUN interface for IP-level networking.

## Core Architecture

### 4-Layer Stack
1. **Transport** (`udp.rs`) → Raw UDP socket for underlay
2. **Crypto** (`crypto.rs`, `session.rs`) → Noise_XX_25519_ChaChaPoly_BLAKE2s handshakes
3. **Protocol** (`protocol.rs`) → SwitchHeader (20 bytes) + encrypted payload
4. **Routing** (`router.rs`, `topology.rs`) → Hyperbolic greedy forwarding

### Critical Data Flow
```
TUN device → IP packet → encrypt via Session → AxiomPacket → UDP sendto
UDP recvfrom → AxiomPacket → decrypt via Session → TUN device → IP stack
```

### Key Components
- **`AxiomNode`** (`main.rs`): Main orchestrator holding router, sessions, UDP socket, TUN device
- **`Session`** (`session.rs`): Per-peer Noise protocol state (handshaking → established)
- **`RoutingTable`** (`router.rs`): Stores peer coords and direct routes
- **`Coordinates`** (`topology.rs`): Hyperbolic coords (r, theta) in Poincaré disk

## Critical Patterns

### Identity Generation
- **Ed25519 keypairs** generated/loaded via `crypto::NodeIdentity`
- **Overlay IPv6**: `fc00::/8` prefix + BLAKE2s(public_key)[120 bits] (see `identity.rs`)
- Keys stored in `./config/identity.key` (64 bytes: private||public)

### Session Management
Sessions indexed by `peer_id` (u32) in `DashMap<u32, Session>`:
- **Handshake flow**: Initiator sends Handshake packet → Responder creates session → Established
- **Data flow**: Established sessions encrypt/decrypt using Noise TransportState
- **Session IDs**: Atomic counter incremented per new peer

### Packet Types (see `protocol.rs`)
```rust
0 = Data        // Encrypted IP packets
1 = Control     // Heartbeats with coords/load (bincode serialized)
2 = Handshake   // Noise protocol messages
3 = Keepalive   // Connection maintenance
```

### Hyperbolic Routing
- Peers stored with `Coordinates { r: f64, theta: f64 }` (polar)
- **Distance formula**: `acosh(1 + 2|u-v|² / ((1-|u|²)(1-|v|²)))`
- **Greedy forwarding**: Select neighbor closest to destination in hyperbolic space
- See `topology::find_greedy_hop()` for implementation

### Control Plane
- **Heartbeats** sent every 5 seconds with self coordinates and load
- `ControlMessage::Heartbeat` updates routing table peer entries
- No DHT implementation yet (coordinates currently random at startup)

## Build & Run

### Build
```powershell
cargo build          # Debug build
cargo build --release # Production build
```

### Run Node
```powershell
# Node 1 (bootstrap)
cargo run -- --bind 0.0.0.0:9000 --tun ax0 --node-id node1

# Node 2 (connecting to node1)
cargo run -- --bind 0.0.0.0:9001 --tun ax1 --peer 127.0.0.1:9000 --node-id node2
```

### TUN Interface Notes
- **Windows**: Requires TAP-Windows adapter (Wintun/WireGuard driver)
- TUN failures are **non-fatal** - daemon runs in UDP-only mode
- Default MTU: 1500, default IP: fd00::1, netmask: ffff:ffff:ffff:ffff::

## Development Conventions

### Error Handling
- Use `anyhow::Result` for all fallible functions
- Log errors with `tracing::warn!` or `tracing::error!`, don't panic
- Return `Ok(())` to continue processing on non-fatal errors

### Async Patterns
- All I/O uses **Tokio async runtime** (`#[tokio::main]`)
- Main loop uses `tokio::select!` for concurrent UDP/TUN reads
- Spawned tasks (heartbeat loop) use `Arc` for shared state

### Logging
- **tracing** crate with `RUST_LOG` env var (e.g., `RUST_LOG=debug`)
- Use `trace!` for per-packet, `debug!` for events, `info!` for lifecycle, `warn!` for errors

### Data Structures
- **DashMap** for concurrent session/route storage (lock-free)
- **Arc** everywhere for shared ownership across tasks
- **AtomicU64** for counters (send_counter, recv_counter)

## Current Limitations
- **No DHT**: Peer coordinates are random, no distributed lookup
- **No bandwidth market**: Nanopayment system unimplemented
- **No source routing**: Only greedy forwarding
- **No WASM runtime**: Edge compute planned but not implemented
- **Bootstrap only**: Must manually specify --peer, no discovery

## When Editing

### Adding Packet Types
1. Update `PacketType` enum in `protocol.rs`
2. Add handling in `AxiomNode::handle_inbound_udp()`
3. Consider adding to `ControlMessage` if control-plane related

### Adding Routing Strategies
1. Implement algorithm in `topology.rs`
2. Update `AxiomNode::handle_inbound_tun()` decision logic
3. Test with multi-hop scenarios (3+ nodes)

### Debugging Handshake Issues
- Check `snow` crate logs (Noise protocol state machine)
- Verify `receiver_index` and `remote_index` matching
- Ensure initiator/responder roles correct (initiator writes first)

## Testing
- Integration tests in `tests/integration_test.rs` (currently minimal)
- Manual testing: Run 2-3 nodes, ping overlay IPs
- No unit tests yet - add to module files when implementing complex logic

## External Dependencies
- **tun** crate: Async TUN/TAP device interface
- **snow**: Noise protocol implementation
- **dashmap**: Concurrent HashMap
- **bytes**: Zero-copy buffer handling
- **bincode**: Fast binary serialization
