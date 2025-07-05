pub mod ios;
pub mod macos;

use anyhow::Result;
use std::ffi::c_char;

/// Platform-agnostic lifecycle management trait
pub trait LifecycleManager: Send + Sync {
    fn setup_observers(&self, node_handle: *mut crate::node::CNode);
    fn handle_background(&self, node_handle: *mut crate::node::CNode) -> Result<()>;
    fn handle_foreground(&self, node_handle: *mut crate::node::CNode) -> Result<()>;
    fn handle_memory_warning(&self, node_handle: *mut crate::node::CNode) -> Result<()>;
}

/// Factory function for creating platform-specific lifecycle manager
pub fn create_lifecycle_manager() -> Box<dyn LifecycleManager> {
    #[cfg(target_os = "ios")]
    {
        Box::new(ios::IOSLifecycleManager::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOSLifecycleManager::new())
    }
    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    {
        compile_error!("Platform not supported");
    }
}

/// FFI lifecycle management functions
pub mod ffi {
    use super::*;
    use crate::error::{CError, RunarErrorCode};

    /// Setup lifecycle observers for the current platform
    #[no_mangle]
    pub extern "C" fn runar_lifecycle_setup_observers(
        node_handle: *mut crate::node::CNode,
    ) -> CError {
        if node_handle.is_null() {
            return CError::new(
                RunarErrorCode::InvalidParameters,
                "Invalid node handle".to_string(),
                None,
            );
        }

        let lifecycle_manager = create_lifecycle_manager();
        lifecycle_manager.setup_observers(node_handle);

        CError::new(
            RunarErrorCode::Success,
            "Lifecycle observers setup successfully".to_string(),
            None,
        )
    }

    /// Handle app entering background
    #[no_mangle]
    pub extern "C" fn runar_lifecycle_handle_background(
        node_handle: *mut crate::node::CNode,
    ) -> CError {
        if node_handle.is_null() {
            return CError::new(
                RunarErrorCode::InvalidParameters,
                "Invalid node handle".to_string(),
                None,
            );
        }

        let lifecycle_manager = create_lifecycle_manager();
        match lifecycle_manager.handle_background(node_handle) {
            Ok(_) => CError::new(
                RunarErrorCode::Success,
                "Background transition handled".to_string(),
                None,
            ),
            Err(e) => CError::from_anyhow(e.into()),
        }
    }

    /// Handle app entering foreground
    #[no_mangle]
    pub extern "C" fn runar_lifecycle_handle_foreground(
        node_handle: *mut crate::node::CNode,
    ) -> CError {
        if node_handle.is_null() {
            return CError::new(
                RunarErrorCode::InvalidParameters,
                "Invalid node handle".to_string(),
                None,
            );
        }

        let lifecycle_manager = create_lifecycle_manager();
        match lifecycle_manager.handle_foreground(node_handle) {
            Ok(_) => CError::new(
                RunarErrorCode::Success,
                "Foreground transition handled".to_string(),
                None,
            ),
            Err(e) => CError::from_anyhow(e.into()),
        }
    }

    /// Handle memory warning
    #[no_mangle]
    pub extern "C" fn runar_lifecycle_handle_memory_warning(
        node_handle: *mut crate::node::CNode,
    ) -> CError {
        if node_handle.is_null() {
            return CError::new(
                RunarErrorCode::InvalidParameters,
                "Invalid node handle".to_string(),
                None,
            );
        }

        let lifecycle_manager = create_lifecycle_manager();
        match lifecycle_manager.handle_memory_warning(node_handle) {
            Ok(_) => CError::new(
                RunarErrorCode::Success,
                "Memory warning handled".to_string(),
                None,
            ),
            Err(e) => CError::from_anyhow(e.into()),
        }
    }
}
