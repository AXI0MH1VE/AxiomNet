//! TUN interface abstraction for Axiom
// Platform-specific implementation for Linux, macOS, Windows

pub struct TunInterface {
    // TODO: Add fields for file descriptor, name, etc.
}

impl TunInterface {
    pub fn new(name: &str, mtu: u16) -> Self {
        // TODO: Platform-specific TUN creation
        Self {}
    }
    pub fn read_packet(&self, buf: &mut [u8]) -> usize {
        // TODO: Read from TUN
        0
    }
    pub fn write_packet(&self, buf: &[u8]) -> usize {
        // TODO: Write to TUN
        0
    }
}
