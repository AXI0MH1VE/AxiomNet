use anyhow::{Result, Context};
use snow::{HandshakeState, TransportState};
use crate::protocol::{AxiomPacket, SwitchHeader, PacketType};
use bytes::{Bytes, BytesMut};
use std::sync::atomic::{AtomicU64, Ordering};

pub enum SessionState {
    Handshaking(HandshakeState),
    Established(TransportState),
}

pub struct Session {
    pub state: SessionState,
    pub receiver_index: u32,
    pub remote_index: u32,
    pub send_counter: AtomicU64,
    pub recv_counter: AtomicU64,
}

impl Session {
    pub fn new_handshaking(hs: HandshakeState, receiver_index: u32, remote_index: u32) -> Self {
        Self {
            state: SessionState::Handshaking(hs),
            receiver_index,
            remote_index,
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
        }
    }
    pub fn new_established(ts: TransportState, receiver_index: u32, remote_index: u32) -> Self {
        Self {
            state: SessionState::Established(ts),
            receiver_index,
            remote_index,
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
        }
    }

    pub fn is_established(&self) -> bool {
        matches!(self.state, SessionState::Established(_))
    }

    pub fn process_incoming(&mut self, packet: AxiomPacket) -> Result<Bytes> {
        match &mut self.state {
            SessionState::Handshaking(hs) => {
                let mut out = [0u8; 2048];
                let n = hs.read_message(&packet.payload, &mut out)?;
                if hs.is_handshake_finished() {
                    let ts = hs.clone().into_transport_mode()?;
                    self.state = SessionState::Established(ts);
                }
                Ok(Bytes::copy_from_slice(&out[..n]))
            }
            SessionState::Established(ts) => {
                let mut out = [0u8; 2048];
                let n = ts.read_message(&packet.payload, &mut out)?;
                self.recv_counter.fetch_add(1, Ordering::SeqCst);
                Ok(Bytes::copy_from_slice(&out[..n]))
            }
        }
    }

    pub fn encrypt_outgoing(&mut self, payload: &[u8]) -> Result<AxiomPacket> {
        match &mut self.state {
            SessionState::Established(ts) => {
                let mut out = [0u8; 2048];
                let n = ts.write_message(payload, &mut out)?;
                let counter = self.send_counter.fetch_add(1, Ordering::SeqCst);
                let header = SwitchHeader {
                    route_label: 0,
                    version: 1,
                    packet_type: PacketType::Data,
                    receiver_index: self.remote_index,
                    counter,
                };
                Ok(AxiomPacket {
                    header,
                    payload: Bytes::copy_from_slice(&out[..n]),
                })
            }
            _ => Err(anyhow::anyhow!("Session not established")),
        }
    }
}
