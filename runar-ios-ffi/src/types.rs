use serde::{Deserialize, Serialize};
use std::ffi::c_char;

/// Log levels for the Runar system
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RunarLogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

/// Keychain accessibility options for iOS
#[cfg(target_os = "ios")]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeychainAccessible {
    WhenUnlocked = 0,
    WhenUnlockedThisDeviceOnly = 1,
    AfterFirstUnlock = 2,
    AfterFirstUnlockThisDeviceOnly = 3,
}

/// C-compatible node configuration
#[repr(C)]
pub struct CNodeConfig {
    pub node_id: *const c_char,
    pub default_network_id: *const c_char,
    pub request_timeout_ms: u64,
    pub log_level: RunarLogLevel,
    pub enable_discovery: bool,
    pub multicast_group: *const c_char,
    pub discovery_port: u16,
    pub max_peers: u32,
}

/// C-compatible data result structure
#[repr(C)]
pub struct CDataResult {
    pub data: *const u8,
    pub length: usize,
    pub error: *const crate::error::CError,
}

impl CDataResult {
    pub fn new(data: *const u8, length: usize) -> Self {
        Self {
            data,
            length,
            error: std::ptr::null(),
        }
    }

    pub fn with_error(error: crate::error::CError) -> Self {
        Self {
            data: std::ptr::null(),
            length: 0,
            error: &error,
        }
    }
}

/// C-compatible node information
#[repr(C)]
pub struct CNodeInfo {
    pub node_id: *const c_char,
    pub network_id: *const c_char,
    pub is_running: bool,
    pub peer_count: u32,
    pub service_count: u32,
}

/// C-compatible peer information
#[repr(C)]
pub struct CPeerInfo {
    pub node_id: *const c_char,
    pub network_id: *const c_char,
    pub address: *const c_char,
    pub port: u16,
    pub is_connected: bool,
    pub last_seen: u64,
}

/// C-compatible service information
#[repr(C)]
pub struct CServiceInfo {
    pub name: *const c_char,
    pub path: *const c_char,
    pub version: *const c_char,
    pub description: *const c_char,
    pub network_id: *const c_char,
}

/// Rust-side configuration structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: String,
    pub default_network_id: String,
    pub request_timeout_ms: u64,
    pub log_level: RunarLogLevel,
    pub network_config: NetworkConfig,
    pub keychain_config: Option<KeychainConfig>,
}

impl NodeConfig {
    pub fn new(node_id: String, default_network_id: String) -> Self {
        Self {
            node_id,
            default_network_id,
            request_timeout_ms: 30000,
            log_level: RunarLogLevel::Info,
            network_config: NetworkConfig::default(),
            keychain_config: None,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.request_timeout_ms = timeout_ms;
        self
    }

    pub fn with_log_level(mut self, level: RunarLogLevel) -> Self {
        self.log_level = level;
        self
    }

    pub fn with_network_config(mut self, config: NetworkConfig) -> Self {
        self.network_config = config;
        self
    }

    pub fn with_keychain_config(mut self, config: KeychainConfig) -> Self {
        self.keychain_config = Some(config);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub enable_discovery: bool,
    pub multicast_group: String,
    pub discovery_port: u16,
    pub max_peers: u32,
    #[cfg(target_os = "ios")]
    pub use_wifi_only: bool,
    #[cfg(target_os = "ios")]
    pub allow_cellular_discovery: bool,
    #[cfg(target_os = "macos")]
    pub bind_to_interface: Option<String>,
    #[cfg(target_os = "macos")]
    pub enable_ipv6: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enable_discovery: true,
            multicast_group: "239.255.42.98".to_string(),
            discovery_port: 4242,
            max_peers: 100,
            #[cfg(target_os = "ios")]
            use_wifi_only: false,
            #[cfg(target_os = "ios")]
            allow_cellular_discovery: true,
            #[cfg(target_os = "macos")]
            bind_to_interface: None,
            #[cfg(target_os = "macos")]
            enable_ipv6: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeychainConfig {
    pub service_name: String,
    pub access_group: Option<String>,
    pub require_biometric: bool,
    pub allow_background_access: bool,
    #[cfg(target_os = "ios")]
    pub use_secure_enclave: bool,
    #[cfg(target_os = "ios")]
    pub accessible_when: KeychainAccessible,
    #[cfg(target_os = "macos")]
    pub use_touch_id: bool,
    #[cfg(target_os = "macos")]
    pub allow_application_password: bool,
}

impl KeychainConfig {
    pub fn new(service_name: String) -> Self {
        Self {
            service_name,
            access_group: None,
            require_biometric: false,
            allow_background_access: false,
            #[cfg(target_os = "ios")]
            use_secure_enclave: true,
            #[cfg(target_os = "ios")]
            accessible_when: KeychainAccessible::WhenUnlocked,
            #[cfg(target_os = "macos")]
            use_touch_id: false,
            #[cfg(target_os = "macos")]
            allow_application_password: true,
        }
    }

    pub fn with_access_group(mut self, group: String) -> Self {
        self.access_group = Some(group);
        self
    }

    pub fn with_biometric_auth(mut self, enabled: bool) -> Self {
        self.require_biometric = enabled;
        self
    }

    #[cfg(target_os = "ios")]
    pub fn with_secure_enclave(mut self, enabled: bool) -> Self {
        self.use_secure_enclave = enabled;
        self
    }

    #[cfg(target_os = "macos")]
    pub fn with_touch_id(mut self, enabled: bool) -> Self {
        self.use_touch_id = enabled;
        self
    }
}

/// Rust-side information structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub network_id: String,
    pub is_running: bool,
    pub peer_count: u32,
    pub service_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: String,
    pub network_id: String,
    pub address: String,
    pub port: u16,
    pub is_connected: bool,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub path: String,
    pub version: String,
    pub description: String,
    pub network_id: Option<String>,
}

/// Utility functions for converting between C and Rust types
pub fn c_node_config_to_rust(config: &CNodeConfig) -> Option<NodeConfig> {
    let node_id = crate::memory::c_string_to_rust(config.node_id)?;
    let default_network_id = crate::memory::c_string_to_rust(config.default_network_id)?;

    let mut network_config = NetworkConfig::default();
    network_config.enable_discovery = config.enable_discovery;
    network_config.discovery_port = config.discovery_port;
    network_config.max_peers = config.max_peers;

    if let Some(multicast_group) = crate::memory::c_string_to_rust(config.multicast_group) {
        network_config.multicast_group = multicast_group;
    }

    Some(NodeConfig {
        node_id,
        default_network_id,
        request_timeout_ms: config.request_timeout_ms,
        log_level: config.log_level,
        network_config,
        keychain_config: None,
    })
}

pub fn rust_node_config_to_c(config: &NodeConfig) -> CNodeConfig {
    CNodeConfig {
        node_id: crate::memory::rust_string_to_c(&config.node_id),
        default_network_id: crate::memory::rust_string_to_c(&config.default_network_id),
        request_timeout_ms: config.request_timeout_ms,
        log_level: config.log_level,
        enable_discovery: config.network_config.enable_discovery,
        multicast_group: crate::memory::rust_string_to_c(&config.network_config.multicast_group),
        discovery_port: config.network_config.discovery_port,
        max_peers: config.network_config.max_peers,
    }
}

pub fn rust_node_info_to_c(info: &NodeInfo) -> CNodeInfo {
    CNodeInfo {
        node_id: crate::memory::rust_string_to_c(&info.node_id),
        network_id: crate::memory::rust_string_to_c(&info.network_id),
        is_running: info.is_running,
        peer_count: info.peer_count,
        service_count: info.service_count,
    }
}

pub fn rust_peer_info_to_c(info: &PeerInfo) -> CPeerInfo {
    CPeerInfo {
        node_id: crate::memory::rust_string_to_c(&info.node_id),
        network_id: crate::memory::rust_string_to_c(&info.network_id),
        address: crate::memory::rust_string_to_c(&info.address),
        port: info.port,
        is_connected: info.is_connected,
        last_seen: info.last_seen,
    }
}

pub fn rust_service_info_to_c(info: &ServiceInfo) -> CServiceInfo {
    CServiceInfo {
        name: crate::memory::rust_string_to_c(&info.name),
        path: crate::memory::rust_string_to_c(&info.path),
        version: crate::memory::rust_string_to_c(&info.version),
        description: crate::memory::rust_string_to_c(&info.description),
        network_id: info
            .network_id
            .as_ref()
            .map(|s| crate::memory::rust_string_to_c(s))
            .unwrap_or(std::ptr::null_mut()),
    }
}
