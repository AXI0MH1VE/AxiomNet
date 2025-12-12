use anyhow::Result;
use blake2::{Blake2s256, Digest};
use std::net::Ipv6Addr;

/// Generate a Cryptographically Generated Address (CGA) for Axiom
/// Spec: Prefix 0xfc, BLAKE2s(public_key) truncated to 120 bits
pub fn generate_axiom_address(public_key: &[u8]) -> Result<Ipv6Addr> {
    let mut hasher = Blake2s256::new();
    hasher.update(public_key);
    let hash = hasher.finalize(); // 32 bytes
    // Truncate to 120 bits (15 bytes)
    let mut addr_bytes = [0u8; 16];
    addr_bytes[0] = 0xfc; // ULA prefix
    addr_bytes[1..16].copy_from_slice(&hash[..15]);
    Ok(Ipv6Addr::from(addr_bytes))
}
