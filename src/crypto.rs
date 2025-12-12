use anyhow::{Result, Context};
use base64::{engine::general_purpose, Engine as _};
use snow::{Builder, HandshakeState, params::NoiseParams, Keypair, TransportState};
use std::fs;
use std::path::Path;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

pub struct NodeIdentity {
    pub static_keypair: Keypair,
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
        if path.as_ref().exists() {
            let key_bytes = fs::read(path)?;
            let static_keypair = Keypair {
                private: key_bytes[..32].try_into().context("Invalid private key length")?,
                public: key_bytes[32..].try_into().context("Invalid public key length")?,
            };
            Ok(Self { static_keypair })
        } else {
            let params: NoiseParams = NOISE_PARAMS.parse().context("Invalid Noise params")?;
            let builder = Builder::new(params);
            let static_keypair = builder.generate_keypair().context("Failed to generate static keypair")?;
            let mut key_bytes = Vec::new();
            key_bytes.extend_from_slice(&static_keypair.private);
            key_bytes.extend_from_slice(&static_keypair.public);
            fs::write(path, &key_bytes)?;
            Ok(Self { static_keypair })
        }
    }

    pub fn public_base64(&self) -> String {
        general_purpose::STANDARD.encode(&self.static_keypair.public)
    }
}

pub struct HandshakeManager {
    state: HandshakeState,
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
