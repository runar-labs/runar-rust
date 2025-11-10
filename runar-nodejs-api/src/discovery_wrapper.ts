import { decode } from 'cbor-x';

import type { Keys, Discovery as NativeDiscoveryType } from '../index.d';

/**
 * PeerInfo structure matching runar_transporter::discovery::PeerInfo
 */
export interface PeerInfo {
  publicKey: Buffer;
  addresses: string[];
}

/**
 * Discovery options matching runar_transporter::discovery::DiscoveryOptions
 */
export interface DiscoveryOptions {
  announceIntervalMs?: number;
  discoveryTimeoutMs?: number;
  debounceWindowMs?: number;
  useMulticast?: boolean;
  localNetworkOnly?: boolean;
  multicastGroup?: string;
  localAddresses?: string[];
}

/**
 * Callback for discovered peers
 */
export interface DiscoveredCallback {
  (peerInfo: PeerInfo): void | Promise<void>;
}

/**
 * Callback for updated peers
 */
export interface UpdatedCallback {
  (peerInfo: PeerInfo): void | Promise<void>;
}

/**
 * Callback for lost peers
 */
export interface LostCallback {
  (peerId: string): void | Promise<void>;
}

/**
 * Discovery - High-level TypeScript wrapper around native multicast discovery
 * 
 * This class provides a clean, idiomatic TypeScript API that matches the Rust
 * NodeDiscovery trait interface while internally using a polling mechanism to
 * bridge Rust callbacks to JavaScript.
 * 
 * Matches the Rust API from runar_transporter::discovery::NodeDiscovery:
 * - init(options)
 * - start_announcing()
 * - stop_announcing()
 * - shutdown()
 * - update_local_peer_info(peerInfo)
 * - subscribe(listener) -> exposed as onDiscovered/onUpdated/onLost callbacks
 */
export class Discovery {
  private native: NativeDiscoveryType;
  private polling: boolean = false;
  private pollInterval: NodeJS.Timeout | null = null;
  
  public onDiscovered?: DiscoveredCallback;
  public onUpdated?: UpdatedCallback;
  public onLost?: LostCallback;

  constructor(keys: Keys, options: DiscoveryOptions) {
    const { Discovery: NativeDiscovery } = require('../index');
    
    // Convert options to CBOR
    const optionsCbor = Buffer.from(
      require('cbor-x').encode({
        announce_interval_ms: options.announceIntervalMs,
        discovery_timeout_ms: options.discoveryTimeoutMs,
        debounce_window_ms: options.debounceWindowMs,
        use_multicast: options.useMulticast,
        local_network_only: options.localNetworkOnly,
        multicast_group: options.multicastGroup,
        local_addresses: options.localAddresses || [],
      })
    );
    
    this.native = new NativeDiscovery(keys, optionsCbor);
    
    // Start polling immediately
    this.startPolling();
  }

  /**
   * Initialize the discovery mechanism (matches NodeDiscovery::init)
   */
  async init(options: DiscoveryOptions): Promise<void> {
    const optionsCbor = Buffer.from(
      require('cbor-x').encode({
        announce_interval_ms: options.announceIntervalMs,
        discovery_timeout_ms: options.discoveryTimeoutMs,
        debounce_window_ms: options.debounceWindowMs,
        use_multicast: options.useMulticast,
        local_network_only: options.localNetworkOnly,
        multicast_group: options.multicastGroup,
      })
    );
    await this.native.init(optionsCbor);
  }

  /**
   * Start announcing this node's presence (matches NodeDiscovery::start_announcing)
   */
  async startAnnouncing(): Promise<void> {
    await this.native.startAnnouncing();
  }

  /**
   * Stop announcing this node's presence (matches NodeDiscovery::stop_announcing)
   */
  async stopAnnouncing(): Promise<void> {
    await this.native.stopAnnouncing();
  }

  /**
   * Shutdown the discovery mechanism (matches NodeDiscovery::shutdown)
   */
  async shutdown(): Promise<void> {
    this.stopPolling();
    await this.native.shutdown();
  }

  /**
   * Update local peer information (matches NodeDiscovery::update_local_peer_info)
   */
  async updateLocalPeerInfo(peerInfo: PeerInfo): Promise<void> {
    const peerInfoCbor = Buffer.from(
      require('cbor-x').encode({
        public_key: Array.from(peerInfo.publicKey),
        addresses: peerInfo.addresses,
      })
    );
    await this.native.updateLocalPeerInfo(peerInfoCbor);
  }

  /**
   * Bind discovery events to transport (auto-connect discovered peers)
   * This is a convenience method not in the base NodeDiscovery trait
   */
  async bindEventsToTransport(transport: any): Promise<void> {
    await this.native.bindEventsToTransport(transport);
  }

  // Internal: Start polling for events
  private startPolling(): void {
    if (this.polling) return;
    this.polling = true;
    
    // Poll immediately, then every 10ms
    this.pollOnce();
    this.pollInterval = setInterval(() => this.pollOnce(), 10);
  }

  // Internal: Stop polling for events
  private stopPolling(): void {
    this.polling = false;
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  // Internal: Poll once for all event types
  private async pollOnce(): Promise<void> {
    if (!this.polling) return;

    try {
      // Poll for discovered peers
      const discoveredBuffer = await this.native.pollDiscovered();
      if (discoveredBuffer && this.onDiscovered) {
        const peerInfo = decode(discoveredBuffer) as { public_key: number[], addresses: string[] };
        await this.onDiscovered({
          publicKey: Buffer.from(peerInfo.public_key),
          addresses: peerInfo.addresses,
        });
      }

      // Poll for updated peers
      const updatedBuffer = await this.native.pollUpdated();
      if (updatedBuffer && this.onUpdated) {
        const peerInfo = decode(updatedBuffer) as { public_key: number[], addresses: string[] };
        await this.onUpdated({
          publicKey: Buffer.from(peerInfo.public_key),
          addresses: peerInfo.addresses,
        });
      }

      // Poll for lost peers
      const lostPeerId = await this.native.pollLost();
      if (lostPeerId && this.onLost) {
        await this.onLost(lostPeerId);
      }
    } catch (error) {
      console.error('Error polling discovery events:', error);
    }
  }
}

