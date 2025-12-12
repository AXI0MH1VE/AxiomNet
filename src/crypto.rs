use anyhow::{Result, Context};
use base64::{engine::general_purpose, Engine as _};
use snow::{Builder, HandshakeState, params::NoiseParams, Keypair, TransportState};
use std::fs;
use std::path::Path;
use blake2::{Blake2s256, Digest};

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod crypto_tests;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

pub struct NodeIdentity {
    pub static_keypair: Keypair,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("public_key", &general_purpose::STANDARD.encode(&self.static_keypair.public))
            .finish_non_exhaustive()
    }
}

impl NodeIdentity {
    pub fn load_from_hex(hex_key: &str) -> Result<Self> {
        let bytes = hex::decode(hex_key.trim())?;
        if bytes.len() != 64 {
            anyhow::bail!("Hex key must be 64 bytes (private||public)");
        }
        let static_keypair = Keypair {
            private: bytes[..32].try_into().context("Invalid private key length")?,
            public: bytes[32..].try_into().context("Invalid public key length")?,
        };
        Ok(Self { static_keypair })
    }

    pub fn load_or_generate<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        
        // Ensure parent directory exists to prevent write failures
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create config directory")?;
        }
        
        if path.exists() {
            let key_bytes = fs::read(path)
                .context("Failed to read identity key file")?;
            
            // Validate key integrity before using and extract keypair
            let static_keypair = Self::verify_key_integrity(&key_bytes)
                .context("Identity key file corrupted")?;
            
            Ok(Self { static_keypair })
        } else {
            let params: NoiseParams = NOISE_PARAMS.parse().context("Invalid Noise params")?;
            let builder = Builder::new(params);
            let static_keypair = builder.generate_keypair().context("Failed to generate static keypair")?;
            
            let mut key_bytes = Vec::new();
            key_bytes.extend_from_slice(&static_keypair.private);
            key_bytes.extend_from_slice(&static_keypair.public);
            
            // Compute checksum for integrity verification
            let mut hasher = Blake2s256::new();
            hasher.update(&key_bytes);
            let checksum = hasher.finalize();
            
            // Append first 8 bytes of checksum
            key_bytes.extend_from_slice(&checksum[..8]);
            
            // Atomic write: write to temp file, then rename
            // This ensures we never have a partially written key file
            let temp_path = path.with_extension("tmp");
            fs::write(&temp_path, &key_bytes)
                .context("Failed to write temporary key file")?;
            fs::rename(&temp_path, path)
                .context("Failed to atomically rename key file")?;
            
            Ok(Self { static_keypair })
        }
    }
    
    /// Verify key file integrity
    fn verify_key_integrity(key_bytes: &[u8]) -> Result<Keypair> {
        // Check if file has expected format: 64 bytes (key) + 8 bytes (checksum)
        // or legacy format: exactly 64 bytes (no checksum)
        if key_bytes.len() == 64 {
            // Legacy format without checksum - accept but warn
            tracing::warn!("Identity key file uses legacy format without checksum");
            let static_keypair = Keypair {
                private: key_bytes[..32].try_into().context("Invalid private key length")?,
                public: key_bytes[32..].try_into().context("Invalid public key length")?,
            };
            return Ok(static_keypair);
        }
        
        if key_bytes.len() != 72 {
            anyhow::bail!(
                "Key file corrupted: expected 64 or 72 bytes, got {}",
                key_bytes.len()
            );
        }
        
        // Verify checksum
        let key_data = &key_bytes[..64];
        let stored_checksum = &key_bytes[64..72];
        
        let mut hasher = Blake2s256::new();
        hasher.update(key_data);
        let computed_checksum = hasher.finalize();
        
        if stored_checksum != &computed_checksum[..8] {
            anyhow::bail!("Key file checksum mismatch - file may be corrupted");
        }
        
        let static_keypair = Keypair {
            private: key_data[..32].try_into().context("Invalid private key length")?,
            public: key_data[32..].try_into().context("Invalid public key length")?,
        };
        
        Ok(static_keypair)
    }

    pub fn public_base64(&self) -> String {
        general_purpose::STANDARD.encode(&self.static_keypair.public)
    }
}

pub struct HandshakeManager {
    pub state: HandshakeState,
}

impl HandshakeManager {
    pub fn initiator(local: &NodeIdentity, remote_pub: &[u8]) -> Result<Self> {
        let params: NoiseParams = NOISE_PARAMS.parse().context("Invalid Noise params")?;
        let builder = Builder::new(params)
            .local_private_key(&local.static_keypair.private)
            .remote_public_key(remote_pub);
        let state = builder.build_initiator()?;
        Ok(Self { state })
    }

    pub fn responder(local: &NodeIdentity) -> Result<Self> {
        let params: NoiseParams = NOISE_PARAMS.parse().context("Invalid Noise params")?;
        let builder = Builder::new(params)
            .local_private_key(&local.static_keypair.private);
        let state = builder.build_responder()?;
        Ok(Self { state })
    }

    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize> {
        let n = self.state.write_message(payload, out)?;
        Ok(n)
    }

    pub fn read_message(&mut self, msg: &[u8], out: &mut [u8]) -> Result<usize> {
        let n = self.state.read_message(msg, out)?;
        Ok(n)
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn into_transport(self) -> Result<TransportState> {
        Ok(self.state.into_transport_mode()?)
    }
}
