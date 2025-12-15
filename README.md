# Axiom Network Architecture

Axiom is a sovereign, Layer 3 overlay network designed to restore the end-to-end principle to the internet. It provides a cryptographically secured, scalable, and decentralized parallel internet, allowing unprecedented connectivity and freedom.

---

## Key Features

- **Layer 3 Overlay**: Utilizes TUN interfaces for advanced networking.
- **Hyperbolic Greedy Routing**: Implements a crystalline topology for efficient connections.
- **Cryptographically Generated IPv6 Addresses**: Employs Ed25519/BLAKE2s algorithms.
- **Secure Transport**: Uses the Noise Protocol over UDP.
- **Decentralized Control**: Features a DHT and gossip-based control plane.
- **Bandwidth Market**: Incorporates probabilistic nanopayments.
- **Edge Compute**: Supports a WASM runtime environment.

---

## Repository Structure

- **`/docs`**: Contains detailed subsystem documentation.
- **`/specs`**: Formal specs for engineering solutions.
- **`/src`**: Includes Rust daemon and protocol modules.
- **`/config`**: Offers example configurations.
- **`/tests`**: Contains stubs for integration tests.

---

## Getting Started

### Prerequisites
Ensure you have the following dependencies installed:
- [Rust](https://www.rust-lang.org/): The programming language used for core development.
- [Cargo](https://doc.rust-lang.org/cargo/): Rust's package manager.
- A UNIX-based operating system (Linux/MacOS) or equivalent Windows setup.

### Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/AXI0MH1VE/AxiomNet.git
   ```
2. **Navigate to the Project Directory**:
   ```bash
   cd AxiomNet
   ```
3. **Explore Documentation**:
   Dive into the `/docs/` directory for a more thorough understanding of subsystems.
4. **Build the Daemon**:
   Navigate to `/src/` and follow the build instructions provided there. Use the following as a general guide:
   ```bash
   cargo build --release
   ```
5. **Run Example Configurations**:
   Modify example configurations in `/config/` to suit your setup, then launch the system.

---

## Contributing

We welcome contributions! To get started:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes.
4. Open a pull request and include clear details about your improvements.

Refer to `/docs/contribution.md` for further guidelines.

---

## License

Currently under consideration. It will either be:

- **MIT License**: Permissive, enabling widespread freedom of use.
- **Apache 2.0 License**: Permissive with a focus on patent protection.

---

## Community & Support

- **Mailing List**: Join discussions and receive updates at [community@axiomnet.dev](mailto:community@axiomnet.dev).
- **Issues**: Report bugs or request features through [GitHub Issues](https://github.com/AXI0MH1VE/AxiomNet/issues).

Stay connected and help us make AxiomNet better for everyone!