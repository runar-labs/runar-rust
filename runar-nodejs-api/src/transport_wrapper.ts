const { Transport: NativeTransport } = require('../index');
const { decode } = require('cbor-x');

import type { Keys, TransportOptions, Transport as NativeTransportType } from '../index.d';

interface RequestReceivedEvent {
  type: 'RequestReceived';
  v: number;
  request_id: string;
  path: string;
  correlation_id: string;
  payload: Buffer;
  source_node_id: string;
  destination_node_id: string;
  profile_public_keys: Buffer[];
  network_public_key?: Buffer;
}

interface EventReceivedEvent {
  type: 'EventReceived';
  v: number;
  path: string;
  correlation_id: string;
  payload: Buffer;
  source_node_id: string;
  destination_node_id: string;
  profile_public_keys: Buffer[];
  network_public_key?: Buffer;
}

interface PeerConnectedEvent {
  type: 'PeerConnected';
  v: number;
  peer_id: string;
  node_info: {
    node_public_key: Buffer;
    network_ids: string[];
    addresses: string[];
    version: number;
  };
}

interface PeerDisconnectedEvent {
  type: 'PeerDisconnected';
  v: number;
  peer_node_id: string;
}

type TransportEvent = RequestReceivedEvent | EventReceivedEvent | PeerConnectedEvent | PeerDisconnectedEvent;

export interface RequestCallback {
  (
    requestId: string,
    path: string,
    correlationId: string,
    payload: Buffer,
    sourceNodeId: string,
    destinationNodeId: string,
    profilePublicKeys: Buffer[],
    networkPublicKey?: Buffer
  ): Promise<{ payload: Buffer; profilePublicKeys: Buffer[] }>;
}

export interface EventCallback {
  (
    path: string,
    correlationId: string,
    payload: Buffer,
    sourceNodeId: string,
    destinationNodeId: string,
    profilePublicKeys: Buffer[],
    networkPublicKey?: Buffer
  ): void;
}

export interface PeerConnectedCallback {
  (
    peerId: string,
    nodeInfo: {
      nodePublicKey: Buffer;
      networkIds: string[];
      addresses: string[];
      version: number;
    }
  ): void;
}

export interface PeerDisconnectedCallback {
  (peerNodeId: string): void;
}

/**
 * Transport - High-level TypeScript wrapper around native QUIC transport
 * 
 * This class provides a clean, idiomatic TypeScript API while internally
 * using a polling mechanism to bridge Rust callbacks to JavaScript.
 */
export class Transport {
  private native: NativeTransportType;
  private polling: boolean = false;
  private pollInterval: NodeJS.Timeout | null = null;
  private started: boolean = false;
  
  public onRequest?: RequestCallback;
  public onEvent?: EventCallback;
  public onPeerConnected?: PeerConnectedCallback;
  public onPeerDisconnected?: PeerDisconnectedCallback;

  constructor(keys: Keys, options: TransportOptions) {
    this.native = new NativeTransport(keys, options);
  }

  /**
   * Start the transport and begin event polling
   */
  async start(): Promise<void> {
    await this.native.start();
    this.started = true;
    this.startPolling();
  }

  /**
   * Stop the transport and event polling
   */
  async stop(): Promise<void> {
    this.stopPolling();
    
    if (!this.started) {
      // Not started yet, nothing to stop on native side
      return;
    }
    
    try {
      await this.native.stop();
      this.started = false;
    } catch (error) {
      // Ignore errors if transport wasn't started or already stopped
      this.started = false;
    }
  }

  /**
   * Send a request and wait for response
   */
  async request(
    path: string,
    correlationId: string,
    payload: Buffer,
    destPeerId: string,
    networkPublicKey?: Buffer,
    profilePublicKeys: Buffer[] = []
  ): Promise<Buffer> {
    return await this.native.request(
      path,
      correlationId,
      payload,
      destPeerId,
      networkPublicKey,
      profilePublicKeys
    );
  }

  /**
   * Publish an event (fire-and-forget)
   */
  async publish(
    path: string,
    correlationId: string,
    payload: Buffer,
    destPeerId: string,
    networkPublicKey?: Buffer
  ): Promise<void> {
    await this.native.publish(
      path,
      correlationId,
      payload,
      destPeerId,
      networkPublicKey
    );
  }

  /**
   * Connect to a peer
   */
  async connectPeer(peerInfoCbor: Buffer): Promise<void> {
    await this.native.connectPeer(peerInfoCbor);
  }

  /**
   * Check if connected to a peer
   */
  async isConnected(peerId: string): Promise<boolean> {
    return await this.native.isConnected(peerId);
  }

  /**
   * Get local address
   */
  getLocalAddr(): string {
    return this.native.getLocalAddr();
  }

  /**
   * Update local node info
   */
  async updateLocalNodeInfo(nodeInfoCbor: Buffer): Promise<void> {
    await this.native.updateLocalNodeInfo(nodeInfoCbor);
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

  // Internal: Poll once for events
  private async pollOnce(): Promise<void> {
    if (!this.polling) return;

    try {
      const eventBuffer = await this.native.pollEvent();
      if (!eventBuffer) return;

      const event = decode(eventBuffer) as TransportEvent;
      
      switch (event.type) {
        case 'RequestReceived':
          await this.handleRequestReceived(event);
          break;
        case 'EventReceived':
          this.handleEventReceived(event);
          break;
        case 'PeerConnected':
          this.handlePeerConnected(event);
          break;
        case 'PeerDisconnected':
          this.handlePeerDisconnected(event);
          break;
      }
    } catch (err) {
      console.error('Error polling transport event:', err);
    }
  }

  private async handleRequestReceived(event: RequestReceivedEvent): Promise<void> {
    if (!this.onRequest) {
      console.warn('Received request but no onRequest handler set');
      // Send empty response to unblock the sender
      await this.native.completeRequest(event.request_id, Buffer.alloc(0), []);
      return;
    }

    try {
      const response = await this.onRequest(
        event.request_id,
        event.path,
        event.correlation_id,
        event.payload,
        event.source_node_id,
        event.destination_node_id,
        event.profile_public_keys,
        event.network_public_key
      );
      
      await this.native.completeRequest(
        event.request_id,
        response.payload,
        response.profilePublicKeys
      );
    } catch (err) {
      console.error('Error handling request:', err);
      // Send empty response to unblock the sender
      await this.native.completeRequest(event.request_id, Buffer.alloc(0), []);
    }
  }

  private handleEventReceived(event: EventReceivedEvent): void {
    if (!this.onEvent) return;
    
    try {
      this.onEvent(
        event.path,
        event.correlation_id,
        event.payload,
        event.source_node_id,
        event.destination_node_id,
        event.profile_public_keys,
        event.network_public_key
      );
    } catch (err) {
      console.error('Error handling event:', err);
    }
  }

  private handlePeerConnected(event: PeerConnectedEvent): void {
    if (!this.onPeerConnected) return;
    
    try {
      this.onPeerConnected(event.peer_id, {
        nodePublicKey: event.node_info.node_public_key,
        networkIds: event.node_info.network_ids,
        addresses: event.node_info.addresses,
        version: event.node_info.version,
      });
    } catch (err) {
      console.error('Error handling peer connected:', err);
    }
  }

  private handlePeerDisconnected(event: PeerDisconnectedEvent): void {
    if (!this.onPeerDisconnected) return;
    
    try {
      this.onPeerDisconnected(event.peer_node_id);
    } catch (err) {
      console.error('Error handling peer disconnected:', err);
    }
  }
}

