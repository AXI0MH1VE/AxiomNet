// Unit tests for crypto key persistence and integrity

use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use crate::crypto::NodeIdentity;

#[test]
fn test_load_or_generate_creates_directory() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_path = temp_dir.path().join("subdir").join("identity.key");
    
    // Directory doesn't exist yet
    assert!(!key_path.parent().unwrap().exists());
    
    // Should create directory and key file
    let identity = NodeIdentity::load_or_generate(&key_path)
        .expect("Should create key and directory");
    
    assert!(key_path.exists(), "Key file should be created");
    assert!(key_path.parent().unwrap().exists(), "Parent directory should be created");
}

#[test]
fn test_load_or_generate_atomic_write() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_path = temp_dir.path().join("identity.key");
    
    // Generate new key
    let _identity = NodeIdentity::load_or_generate(&key_path)
        .expect("Should create key");
    
    // Verify no .tmp file left over (atomic rename completed)
    let temp_path = key_path.with_extension("tmp");
    assert!(!temp_path.exists(), "Temp file should be cleaned up after atomic write");
    
    // Verify key file exists and is valid size
    assert!(key_path.exists(), "Key file should exist");
    let metadata = fs::metadata(&key_path).expect("Should read key file metadata");
    // Should be 64 bytes (key) + 8 bytes (checksum) = 72 bytes
    assert_eq!(metadata.len(), 72, "Key file should be 72 bytes (64 key + 8 checksum)");
}

#[test]
fn test_load_existing_key_with_checksum() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_path = temp_dir.path().join("identity.key");
    
    // Generate key
    let identity1 = NodeIdentity::load_or_generate(&key_path)
        .expect("Should create key");
    let pubkey1 = identity1.public_base64();
    
    // Load same key
    let identity2 = NodeIdentity::load_or_generate(&key_path)
        .expect("Should load existing key");
    let pubkey2 = identity2.public_base64();
    
    assert_eq!(pubkey1, pubkey2, "Loaded key should match generated key");
}

#[test]
fn test_load_legacy_key_without_checksum() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_path = temp_dir.path().join("identity.key");
    
    // Create a legacy 64-byte key file (without checksum)
    let key_bytes = vec![0u8; 64]; // Dummy key data
    fs::write(&key_path, &key_bytes).expect("Should write legacy key");
    
    // Should load without error (with warning)
    let result = NodeIdentity::load_or_generate(&key_path);
    assert!(result.is_ok(), "Should load legacy key format");
}

#[test]
fn test_corrupted_key_detected() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_path = temp_dir.path().join("identity.key");
    
    // Generate valid key
    let _identity = NodeIdentity::load_or_generate(&key_path)
        .expect("Should create key");
    
    // Corrupt the key by changing last byte (checksum)
    let mut key_data = fs::read(&key_path).expect("Should read key file");
    key_data[71] ^= 0xFF; // Flip bits in last checksum byte
    fs::write(&key_path, &key_data).expect("Should write corrupted key");
    
    // Should detect corruption
    let result = NodeIdentity::load_or_generate(&key_path);
    assert!(result.is_err(), "Should detect corrupted key");
    
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("checksum"), "Error should mention checksum mismatch");
}

#[test]
fn test_wrong_size_key_rejected() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_path = temp_dir.path().join("identity.key");
    
    // Write key with wrong size
    let wrong_size_key = vec![0u8; 50]; // Neither 64 nor 72 bytes
    fs::write(&key_path, &wrong_size_key).expect("Should write wrong-size key");
    
    // Should reject
    let result = NodeIdentity::load_or_generate(&key_path);
    assert!(result.is_err(), "Should reject wrong-size key");
    
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("corrupted") || err_msg.contains("expected"), 
        "Error should mention corruption or size mismatch");
}

#[test]
fn test_load_from_hex_valid() {
    // Test loading from valid hex string
    let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
                   fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    
    let result = NodeIdentity::load_from_hex(hex_key);
    assert!(result.is_ok(), "Should load valid hex key");
}

#[test]
fn test_load_from_hex_invalid_length() {
    // Test hex string with wrong length
    let short_hex = "0123456789abcdef";
    
    let result = NodeIdentity::load_from_hex(short_hex);
    assert!(result.is_err(), "Should reject hex key with wrong length");
}

#[test]
fn test_load_from_hex_invalid_chars() {
    // Test hex string with invalid characters
    let invalid_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\
                       zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    
    let result = NodeIdentity::load_from_hex(invalid_hex);
    assert!(result.is_err(), "Should reject hex key with invalid characters");
}

#[test]
fn test_public_base64_format() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_path = temp_dir.path().join("identity.key");
    
    let identity = NodeIdentity::load_or_generate(&key_path)
        .expect("Should create key");
    
    let base64_pubkey = identity.public_base64();
    
    // Should be valid base64
    assert!(!base64_pubkey.is_empty(), "Public key should not be empty");
    // Base64 encoding of 32 bytes should be ~44 characters
    assert!(base64_pubkey.len() >= 40 && base64_pubkey.len() <= 50, 
        "Base64 public key should be reasonable length, got {}", base64_pubkey.len());
}
