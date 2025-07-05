use super::LifecycleManager;
use anyhow::Result;
use std::ffi::c_char;

/// iOS-specific lifecycle manager
pub struct IOSLifecycleManager;

impl IOSLifecycleManager {
    pub fn new() -> Self {
        Self
    }
}

impl LifecycleManager for IOSLifecycleManager {
    fn setup_observers(&self, node_handle: *mut crate::node::CNode) {
        // This function is called from Swift side to register native callbacks
        // The actual observer setup happens in Swift using NotificationCenter
        // This is just a placeholder for the FFI interface
    }

    fn handle_background(&self, node_handle: *mut crate::node::CNode) -> Result<()> {
        if node_handle.is_null() {
            return Err(anyhow::anyhow!("Invalid node handle"));
        }

        let node = unsafe { &*node_handle };
        // Trigger complete node shutdown
        futures::executor::block_on(node.as_ref().handle_background_transition())
    }

    fn handle_foreground(&self, node_handle: *mut crate::node::CNode) -> Result<()> {
        if node_handle.is_null() {
            return Err(anyhow::anyhow!("Invalid node handle"));
        }

        let node = unsafe { &*node_handle };
        // Trigger complete node restart
        futures::executor::block_on(node.as_ref().handle_foreground_transition())
    }

    fn handle_memory_warning(&self, _node_handle: *mut crate::node::CNode) -> Result<()> {
        // Force garbage collection if needed
        // In a real implementation, this would trigger memory cleanup
        Ok(())
    }
}
