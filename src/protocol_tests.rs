// Unit tests for safety-critical protocol parsing

use bytes::Bytes;
use crate::protocol::{SwitchHeader, PacketType, AxiomPacket};

#[test]
fn test_switch_header_decode_truncated_packet() {
    // Test that truncated packets return error instead of panicking
    let short_packet = vec![0u8, 1u8, 2u8, 3u8, 4u8]; // Only 5 bytes
    let mut buf = Bytes::from(short_packet);
    
    let result = SwitchHeader::decode(&mut buf);
    assert!(result.is_err(), "Should return error for truncated packet");
    
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("too short"), "Error should mention packet is too short");
}

#[test]
fn test_switch_header_decode_minimum_valid() {
    // Test that minimum valid packet (16 bytes) is accepted
    let mut buf = bytes::BytesMut::with_capacity(16);
    buf.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // route_label: 1
        0x10,                   // version: 1, packet_type: 0 (Data)
        0x00, 0x00, 0x01,       // receiver_index: 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // counter: 5
    ]);
    
    let mut bytes = buf.freeze();
    let result = SwitchHeader::decode(&mut bytes);
    assert!(result.is_ok(), "Should accept valid 16-byte header");
    
    let header = result.unwrap();
    assert_eq!(header.route_label, 1);
    assert_eq!(header.version, 1);
    assert_eq!(header.packet_type, PacketType::Data);
    assert_eq!(header.receiver_index, 1);
    assert_eq!(header.counter, 5);
}

#[test]
fn test_switch_header_decode_invalid_packet_type() {
    // Test that invalid packet type returns error
    let mut buf = bytes::BytesMut::with_capacity(16);
    buf.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, // route_label: 0
        0x1F,                   // version: 1, packet_type: 15 (invalid)
        0x00, 0x00, 0x00,       // receiver_index: 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // counter: 0
    ]);
    
    let mut bytes = buf.freeze();
    let result = SwitchHeader::decode(&mut bytes);
    assert!(result.is_err(), "Should return error for invalid packet type");
    
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Invalid packet type"), "Error should mention invalid packet type");
}

#[test]
fn test_axiom_packet_roundtrip() {
    // Test that encode/decode is identity for valid packets
    let original = AxiomPacket {
        header: SwitchHeader {
            route_label: 12345,
            version: 1,
            packet_type: PacketType::Control,
            receiver_index: 67890,
            counter: 999,
        },
        payload: Bytes::from_static(b"test payload data"),
    };
    
    let encoded = original.encode();
    let decoded = AxiomPacket::decode(encoded).expect("Should decode successfully");
    
    assert_eq!(decoded.header.route_label, original.header.route_label);
    assert_eq!(decoded.header.version, original.header.version);
    assert_eq!(decoded.header.packet_type, original.header.packet_type);
    assert_eq!(decoded.header.receiver_index, original.header.receiver_index);
    assert_eq!(decoded.header.counter, original.header.counter);
    assert_eq!(decoded.payload, original.payload);
}

#[test]
fn test_axiom_packet_decode_empty() {
    // Test that empty packet returns error
    let empty = Bytes::new();
    let result = AxiomPacket::decode(empty);
    assert!(result.is_err(), "Should return error for empty packet");
}

#[test]
fn test_switch_header_decode_partial_counter() {
    // Test packet with header but truncated counter field
    let mut buf = bytes::BytesMut::with_capacity(10);
    buf.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, // route_label: 0
        0x10,                   // version: 1, packet_type: 0
        0x00, 0x00, 0x00,       // receiver_index: 0
        0x00, 0x00,             // Only 2 bytes of counter (need 8)
    ]);
    
    let mut bytes = buf.freeze();
    let result = SwitchHeader::decode(&mut bytes);
    assert!(result.is_err(), "Should return error for partial counter");
    
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("truncated") || err_msg.contains("expected"),
        "Error should mention truncation or expected bytes, got: {}",
        err_msg
    );
}
