use anyhow::{Result, Context};
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod protocol_tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Data = 0,
    Control = 1,
    Handshake = 2,
    Keepalive = 3,
}

impl PacketType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(PacketType::Data),
            1 => Some(PacketType::Control),
            2 => Some(PacketType::Handshake),
            3 => Some(PacketType::Keepalive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchHeader {
    pub route_label: u32,      // 32 bits
    pub version: u8,          // 4 bits
    pub packet_type: PacketType, // 4 bits
    pub receiver_index: u32,  // 24 bits
    pub counter: u64,         // 64 bits
}

impl SwitchHeader {
    pub const LEN: usize = 20; // 32+4+4+24+64 = 128 bits = 16 bytes, but with alignment/padding, 20 bytes for safe buffer

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.route_label);
        let vt = ((self.version & 0x0F) << 4) | ((self.packet_type as u8) & 0x0F);
        buf.put_u8(vt);
        // receiver_index: 24 bits
        buf.put_u8(((self.receiver_index >> 16) & 0xFF) as u8);
        buf.put_u8(((self.receiver_index >> 8) & 0xFF) as u8);
        buf.put_u8((self.receiver_index & 0xFF) as u8);
        buf.put_u64(self.counter);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        // Check minimum header size to prevent underflow panics
        if buf.remaining() < 16 {
            anyhow::bail!(
                "Packet too short: expected at least 16 bytes for header, got {}",
                buf.len()
            );
        }
        
        let route_label = buf.get_u32();
        let vt = buf.get_u8();
        let version = (vt & 0xF0) >> 4;
        let packet_type = PacketType::from_u8(vt & 0x0F)
            .context("Invalid packet type")?;
        
        // Verify remaining bytes for receiver_index (3 bytes) and counter (8 bytes)
        if buf.remaining() < 11 {
            anyhow::bail!(
                "Packet truncated: expected 11 more bytes for receiver_index and counter, got {}",
                buf.remaining()
            );
        }
        
        let b1 = buf.get_u8();
        let b2 = buf.get_u8();
        let b3 = buf.get_u8();
        let receiver_index = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);
        let counter = buf.get_u64();
        Ok(SwitchHeader {
            route_label,
            version,
            packet_type,
            receiver_index,
            counter,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AxiomPacket {
    pub header: SwitchHeader,
    pub payload: Bytes,
}

impl AxiomPacket {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(SwitchHeader::LEN + self.payload.len());
        self.header.encode(&mut buf);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }

    pub fn decode(mut buf: Bytes) -> Result<Self> {
        let header = SwitchHeader::decode(&mut buf)?;
        let payload = buf;
        Ok(AxiomPacket { header, payload })
    }
}
