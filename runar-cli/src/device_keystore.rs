//! Device keystore helper for platform-specific key storage
//!
//! This module provides a unified interface for creating device keystores
//! across different platforms (macOS, Linux, Windows).

use anyhow::Result;
use runar_keys::keystore::DeviceKeystore;
use std::sync::Arc;

/// Create a platform-specific device keystore
pub fn create_device_keystore_for_platform() -> Result<Arc<dyn DeviceKeystore>> {
    #[cfg(target_os = "macos")]
    {
        use runar_keys::keystore::apple::AppleDeviceKeystore;
        Ok(Arc::new(AppleDeviceKeystore::new("runar-cli")?))
    }
    #[cfg(target_os = "linux")]
    {
        use runar_keys::keystore::linux::LinuxDeviceKeystore;
        Ok(Arc::new(LinuxDeviceKeystore::new(
            "runar-cli",
            "node-keys",
        )?))
    }
    #[cfg(target_os = "windows")]
    {
        // For now, use a simple in-memory keystore for Windows
        // TODO: Implement proper Windows Credential Manager integration
        use runar_keys::keystore::linux::LinuxDeviceKeystore;
        Ok(Arc::new(LinuxDeviceKeystore::new(
            "runar-cli",
            "node-keys",
        )?))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow::anyhow!("Unsupported platform for device keystore"))
    }
}
