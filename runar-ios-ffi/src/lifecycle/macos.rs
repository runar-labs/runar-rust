use super::LifecycleManager;
use anyhow::Result;
use std::ffi::c_char;

/// macOS-specific lifecycle manager
pub struct MacOSLifecycleManager;

impl MacOSLifecycleManager {
    pub fn new() -> Self {
        Self
    }
}

impl LifecycleManager for MacOSLifecycleManager {
    fn setup_observers(&self, node_handle: *mut crate::node::CNode) {
        // This function is called from Swift side to register native callbacks
        // The actual observer setup happens in Swift using NotificationCenter
        // This is just a placeholder for the FFI interface
    }

    fn handle_background(&self, _node_handle: *mut crate::node::CNode) -> Result<()> {
        // macOS apps don't typically background like iOS
        // Just reduce activity but don't stop completely
        Ok(())
    }

    fn handle_foreground(&self, _node_handle: *mut crate::node::CNode) -> Result<()> {
        // Resume full activity
        Ok(())
    }

    fn handle_memory_warning(&self, _node_handle: *mut crate::node::CNode) -> Result<()> {
        // Handle memory pressure
        // In a real implementation, this would trigger memory cleanup
        Ok(())
    }
}
