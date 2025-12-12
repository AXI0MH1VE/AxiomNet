# Axiom Network Architecture

Axiom is a sovereign, Layer 3 overlay network designed to restore the end-to-end principle to the internet. It provides a cryptographically secured, scalable, and decentralized parallel internet, leveraging hyperbolic routing, cryptographic identity, and a crystalline mesh topology.

## Key Features

- Layer 3 overlay using TUN interfaces
- Hyperbolic greedy routing (crystalline topology)
- Cryptographically generated IPv6 addresses (Ed25519/BLAKE2s)
- Noise Protocol over UDP for secure transport
- Decentralized DHT and gossip-based control plane
- Probabilistic nanopayment bandwidth market
- WASM runtime for edge compute

## Repository Structure

- `/docs` — Detailed subsystem documentation
- `/specs` — Formal engineering specifications
- `/src` — Rust daemon and protocol modules
- `/config` — Example configuration files
- `/tests` — Integration test stubs

## Getting Started

1. Clone the repository
2. See `/docs/` for subsystem details
3. Build the daemon in `/src/`

## License

MIT or Apache 2.0 (TBD)
