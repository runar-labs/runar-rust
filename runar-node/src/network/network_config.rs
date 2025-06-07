// Network Configuration
//
// This module provides configuration options for network functionality in the Runar system.

use crate::network::discovery::{DiscoveryOptions, DEFAULT_MULTICAST_ADDR};
use crate::network::transport::{QuicTransportOptions, TransportOptions};
use crate::services::load_balancing::RoundRobinLoadBalancer;
use std::sync::Arc;
use std::time::Duration;

/// Network configuration options
#[derive(Clone, Debug)]
pub struct NetworkConfig {
    /// Load balancing strategy (defaults to round-robin)
    pub load_balancer: Arc<RoundRobinLoadBalancer>,

    /// Transport configuration
    pub transport_type: TransportType,

    /// Base transport options
    pub transport_options: TransportOptions,

    /// QUIC transport options (fully configured)
    pub quic_options: Option<QuicTransportOptions>,

    /// Discovery configuration
    pub discovery_providers: Vec<DiscoveryProviderConfig>,
    pub discovery_options: Option<DiscoveryOptions>,

    /// Advanced options
    pub connection_timeout_ms: u32,
    pub request_timeout_ms: u32,
    pub max_connections: u32,
    pub max_message_size: usize,
    pub max_chunk_size: usize,
}

impl std::fmt::Display for NetworkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NetworkConfig: transport:{:?} bind_address:{} msg_size:{}/{}KB timeout:{}ms",
            self.transport_type,
            self.transport_options.bind_address,
            self.max_message_size / 1024,
            self.max_chunk_size / 1024,
            self.connection_timeout_ms
        )?;

        if let Some(discovery_options) = &self.discovery_options {
            if discovery_options.use_multicast {
                write!(
                    f,
                    " multicast discovery interval:{}ms timeout:{}ms",
                    discovery_options.announce_interval.as_millis(),
                    discovery_options.discovery_timeout.as_millis()
                )?;
            }

            write!(f, " ttl:{}s", discovery_options.node_ttl.as_secs())?;
        }

        Ok(())
    }
}

/// Transport type enum
#[derive(Clone, Debug)]
pub enum TransportType {
    Quic,
    // Add other transport types as needed
}

/// Discovery provider configuration using proper typed options instead of string hashmaps
#[derive(Clone, Debug)]
pub enum DiscoveryProviderConfig {
    /// Multicast discovery configuration
    Multicast(MulticastDiscoveryOptions),

    /// Static discovery configuration
    Static(StaticDiscoveryOptions),
    // Other discovery types can be added here as needed
}

/// Options specific to multicast discovery
#[derive(Clone, Debug)]
pub struct MulticastDiscoveryOptions {
    /// Multicast group address
    pub multicast_group: String,

    /// Announcement interval
    pub announce_interval: Duration,

    /// Discovery timeout
    pub discovery_timeout: Duration,

    /// Time-to-live for discovered nodes
    pub node_ttl: Duration,

    /// Whether to use multicast for discovery
    pub use_multicast: bool,

    /// Whether to only discover on local network
    pub local_network_only: bool,
}

/// Options specific to static discovery
#[derive(Clone, Debug)]
pub struct StaticDiscoveryOptions {
    /// List of static node addresses
    pub node_addresses: Vec<String>,

    /// Refresh interval for checking static nodes
    pub refresh_interval: Duration,
}

impl DiscoveryProviderConfig {
    pub fn default_multicast() -> Self {
        DiscoveryProviderConfig::Multicast(MulticastDiscoveryOptions {
            multicast_group: DEFAULT_MULTICAST_ADDR.to_string(),
            announce_interval: Duration::from_secs(30),
            discovery_timeout: Duration::from_secs(30),
            node_ttl: Duration::from_secs(60),
            use_multicast: true,
            local_network_only: true,
        })
    }

    pub fn default_static(addresses: Vec<String>) -> Self {
        DiscoveryProviderConfig::Static(StaticDiscoveryOptions {
            node_addresses: addresses,
            refresh_interval: Duration::from_secs(60),
        })
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkConfig {
    /// Creates a new network configuration with default settings.
    pub fn new() -> Self {
        Self {
            load_balancer: Arc::new(RoundRobinLoadBalancer::new()),
            transport_type: TransportType::Quic,
            transport_options: TransportOptions::default(),
            quic_options: None,
            discovery_providers: Vec::new(),
            discovery_options: Some(DiscoveryOptions::default()),
            connection_timeout_ms: 60000,
            request_timeout_ms: 10000,
            max_connections: 100,
            max_message_size: 1024 * 1024 * 10, // 10MB default
            max_chunk_size: 1024 * 1024 * 10,   // 10MB default
        }
    }

    /// Create a new NetworkConfig with default QUIC transport settings
    ///
    /// This is a convenience method that sets up a NetworkConfig with:
    /// - Default QUIC transport
    /// - Auto port selection
    /// - Localhost binding
    /// - Secure defaults for connection handling
    pub fn with_quic(quic_options: QuicTransportOptions) -> Self {
        Self {
            load_balancer: Arc::new(RoundRobinLoadBalancer::new()),
            transport_type: TransportType::Quic,
            transport_options: TransportOptions::default(),
            quic_options: Some(quic_options),
            discovery_providers: Vec::new(), // No providers by default
            discovery_options: None,         // No discovery options by default (disabled)
            connection_timeout_ms: 30000,
            request_timeout_ms: 30000,
            max_connections: 100,
            max_message_size: 1024 * 1024, // 1MB
            max_chunk_size: 1024 * 1024,   // 1MB
        }
    }

    pub fn with_transport_type(mut self, transport_type: TransportType) -> Self {
        self.transport_type = transport_type;
        self
    }

    pub fn with_quic_options(mut self, options: QuicTransportOptions) -> Self {
        self.quic_options = Some(options);
        self
    }

    pub fn with_discovery_provider(mut self, provider: DiscoveryProviderConfig) -> Self {
        self.discovery_providers.push(provider);
        self
    }

    pub fn with_discovery_options(mut self, options: DiscoveryOptions) -> Self {
        self.discovery_options = Some(options);
        self
    }

    /// Enable multicast discovery with default settings
    ///
    /// This is a convenience method that configures:
    /// - Default multicast discovery provider
    /// - Default discovery options
    pub fn with_multicast_discovery(mut self) -> Self {
        // Clear existing providers and add the default multicast provider
        self.discovery_providers.clear();
        self.discovery_providers
            .push(DiscoveryProviderConfig::default_multicast());

        // Use default discovery options
        self.discovery_options = Some(DiscoveryOptions::default());

        self
    }
}
