pub mod ios;
pub mod macos;

use anyhow::Result;
use async_trait::async_trait;

/// Common keychain access control configuration
#[derive(Debug, Clone)]
pub struct AccessControl {
    pub require_biometric: bool,
    pub accessible_when: AccessibleWhen,
    pub access_group: Option<String>,
}

#[derive(Debug, Clone)]
pub enum AccessibleWhen {
    WhenUnlocked,
    WhenUnlockedThisDeviceOnly,
    AfterFirstUnlock,
    AfterFirstUnlockThisDeviceOnly,
}

/// Common keychain access trait
#[async_trait]
pub trait KeychainAccess: Send + Sync {
    async fn store_key(
        &self,
        key_id: &str,
        key_data: &[u8],
        access_control: AccessControl,
    ) -> Result<()>;
    async fn retrieve_key(&self, key_id: &str) -> Result<Option<Vec<u8>>>;
    async fn delete_key(&self, key_id: &str) -> Result<()>;
    async fn list_keys(&self) -> Result<Vec<String>>;
    async fn key_exists(&self, key_id: &str) -> Result<bool>;
}

/// Platform-agnostic keychain adapter
pub struct PlatformKeychainAdapter {
    inner: Box<dyn KeychainAccess>,
}

impl PlatformKeychainAdapter {
    pub fn new(inner: Box<dyn KeychainAccess>) -> Self {
        Self { inner }
    }
}

/// Factory function for creating platform-specific keychain
pub fn create_platform_keychain(service_name: String) -> Box<dyn KeychainAccess> {
    #[cfg(target_os = "ios")]
    {
        Box::new(ios::IOSKeychainOperations::new(service_name))
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOSKeychainOperations::new(service_name))
    }
    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    {
        compile_error!("Platform not supported");
    }
}

impl AccessControl {
    pub fn ios_biometric_required() -> Self {
        Self {
            require_biometric: true,
            accessible_when: AccessibleWhen::WhenUnlockedThisDeviceOnly,
            access_group: None,
        }
    }

    pub fn macos_secure_enclave() -> Self {
        Self {
            require_biometric: true,
            accessible_when: AccessibleWhen::WhenUnlocked,
            access_group: None,
        }
    }

    pub fn app_group(group: String) -> Self {
        Self {
            require_biometric: false,
            accessible_when: AccessibleWhen::AfterFirstUnlock,
            access_group: Some(group),
        }
    }
}
