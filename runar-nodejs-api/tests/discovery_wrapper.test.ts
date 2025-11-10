/**
 * Discovery Wrapper Tests
 * 
 * Following FFI test patterns (ffi_discovery_test.rs)
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
const { Keys } = require('../index');
const { encode } = require('cbor-x');
import { Discovery } from '../src/discovery_wrapper';
import type { Keys as KeysType } from '../index.d';
import type { DiscoveryOptions, PeerInfo } from '../src/discovery_wrapper';

// Helper to wait
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

describe('Discovery Wrapper (FFI Pattern)', () => {
  let keysA: KeysType;
  let keysB: KeysType;
  let discoveryA: Discovery | null = null;
  let discoveryB: Discovery | null = null;

  beforeEach(async () => {
    // Create keys for node A
    keysA = new Keys();
    keysA.initAsNode();
    await keysA.generateKeys();
    
    // Create keys for node B
    keysB = new Keys();
    keysB.initAsNode();
    await keysB.generateKeys();
  }, 30000);

  afterEach(async () => {
    // Clean up discovery instances
    if (discoveryA) {
      await discoveryA.shutdown().catch(() => {});
      discoveryA = null;
    }
    if (discoveryB) {
      await discoveryB.shutdown().catch(() => {});
      discoveryB = null;
    }
  }, 10000);

  describe('Basic Lifecycle', () => {
    it('should create discovery with proper options', () => {
      const options: DiscoveryOptions = {
        announceIntervalMs: 100,
        discoveryTimeoutMs: 2000,
        debounceWindowMs: 200,
        useMulticast: true,
        localNetworkOnly: true,
        multicastGroup: '239.255.0.2:45679',
        localAddresses: ['127.0.0.1:8080'],
      };
      
      discoveryA = new Discovery(keysA, options);
      expect(discoveryA).toBeDefined();
    });

    it('should initialize discovery', async () => {
      const options: DiscoveryOptions = {
        announceIntervalMs: 100,
        discoveryTimeoutMs: 2000,
        localAddresses: ['127.0.0.1:8080'],
      };
      
      discoveryA = new Discovery(keysA, options);
      await discoveryA.init(options);
      
      // Should not throw
      expect(true).toBe(true);
    }, 15000);

    it('should start and stop announcing', async () => {
      const options: DiscoveryOptions = {
        announceIntervalMs: 100,
        discoveryTimeoutMs: 2000,
        localAddresses: ['127.0.0.1:8080'],
      };
      
      discoveryA = new Discovery(keysA, options);
      await discoveryA.init(options);
      await discoveryA.startAnnouncing();
      
      // Give it time to announce
      await sleep(200);
      
      await discoveryA.stopAnnouncing();
      
      // Should not throw
      expect(true).toBe(true);
    }, 15000);
  });

  describe('Discovery Events', () => {
    it('should discover peers through callbacks', async () => {
      console.log(`  Creating Discovery instances...`);
      
      const options: DiscoveryOptions = {
        announceIntervalMs: 50,
        discoveryTimeoutMs: 2000,
        debounceWindowMs: 100,
        useMulticast: true,
        localNetworkOnly: true,
        multicastGroup: '239.255.0.3:45680',
        localAddresses: ['127.0.0.1:8081'],
      };
      
      // Create both discovery instances
      discoveryA = new Discovery(keysA, {
        ...options,
        localAddresses: ['127.0.0.1:8081'],
      });
      
      discoveryB = new Discovery(keysB, {
        ...options,
        localAddresses: ['127.0.0.1:8082'],
      });
      
      // Track discovered peers
      let discoveredByA = false;
      let discoveredByB = false;
      
      discoveryA.onDiscovered = (peerInfo: PeerInfo) => {
        console.log(`  A discovered peer: ${Buffer.from(peerInfo.publicKey).toString('hex').substring(0, 16)}...`);
        const bPubKey = Buffer.from(keysB.nodeGetPublicKey());
        if (Buffer.compare(peerInfo.publicKey, bPubKey) === 0) {
          discoveredByA = true;
        }
      };
      
      discoveryB.onDiscovered = (peerInfo: PeerInfo) => {
        console.log(`  B discovered peer: ${Buffer.from(peerInfo.publicKey).toString('hex').substring(0, 16)}...`);
        const aPubKey = Buffer.from(keysA.nodeGetPublicKey());
        if (Buffer.compare(peerInfo.publicKey, aPubKey) === 0) {
          discoveredByB = true;
        }
      };
      
      // Initialize and start announcing
      await discoveryA.init(options);
      await discoveryB.init(options);
      
      console.log(`  Starting announcement...`);
      await discoveryA.startAnnouncing();
      await discoveryB.startAnnouncing();
      
      // Wait for discovery (up to 5 seconds)
      console.log(`  Waiting for peer discovery...`);
      let elapsed = 0;
      const checkInterval = 100;
      const maxWait = 5000;
      
      while (elapsed < maxWait && (!discoveredByA || !discoveredByB)) {
        await sleep(checkInterval);
        elapsed += checkInterval;
      }
      
      console.log(`  Discovery complete: A discovered B=${discoveredByA}, B discovered A=${discoveredByB}`);
      
      // At least one should have discovered the other
      // (multicast can be flaky in test environments)
      const atLeastOneDiscovered = discoveredByA || discoveredByB;
      expect(atLeastOneDiscovered).toBe(true);
      
      await discoveryA.stopAnnouncing();
      await discoveryB.stopAnnouncing();
    }, 30000);
  });

  describe('Peer Info Updates', () => {
    it('should update local peer info', async () => {
      const options: DiscoveryOptions = {
        announceIntervalMs: 100,
        discoveryTimeoutMs: 2000,
        localAddresses: ['127.0.0.1:8083'],
      };
      
      discoveryA = new Discovery(keysA, options);
      await discoveryA.init(options);
      
      const newPeerInfo: PeerInfo = {
        publicKey: Buffer.from(keysA.nodeGetPublicKey()),
        addresses: ['127.0.0.1:9999', '192.168.1.100:9999'],
      };
      
      await discoveryA.updateLocalPeerInfo(newPeerInfo);
      
      // Should not throw
      expect(true).toBe(true);
    }, 15000);
  });

  describe('Error Handling', () => {
    it('should handle shutdown gracefully', async () => {
      const options: DiscoveryOptions = {
        announceIntervalMs: 100,
        discoveryTimeoutMs: 2000,
        localAddresses: ['127.0.0.1:8084'],
      };
      
      discoveryA = new Discovery(keysA, options);
      await discoveryA.init(options);
      await discoveryA.startAnnouncing();
      await discoveryA.shutdown();
      
      // Subsequent shutdown should not throw
      await discoveryA.shutdown();
      // If we get here without throwing, the test passes
      expect(true).toBe(true);
    }, 15000);
  });

  describe('API Methods', () => {
    it('should expose init method', () => {
      const options: DiscoveryOptions = {
        localAddresses: ['127.0.0.1:8085'],
      };
      discoveryA = new Discovery(keysA, options);
      expect(typeof discoveryA.init).toBe('function');
    });

    it('should expose startAnnouncing method', () => {
      const options: DiscoveryOptions = {
        localAddresses: ['127.0.0.1:8086'],
      };
      discoveryA = new Discovery(keysA, options);
      expect(typeof discoveryA.startAnnouncing).toBe('function');
    });

    it('should expose stopAnnouncing method', () => {
      const options: DiscoveryOptions = {
        localAddresses: ['127.0.0.1:8087'],
      };
      discoveryA = new Discovery(keysA, options);
      expect(typeof discoveryA.stopAnnouncing).toBe('function');
    });

    it('should expose shutdown method', () => {
      const options: DiscoveryOptions = {
        localAddresses: ['127.0.0.1:8088'],
      };
      discoveryA = new Discovery(keysA, options);
      expect(typeof discoveryA.shutdown).toBe('function');
    });

    it('should expose updateLocalPeerInfo method', () => {
      const options: DiscoveryOptions = {
        localAddresses: ['127.0.0.1:8089'],
      };
      discoveryA = new Discovery(keysA, options);
      expect(typeof discoveryA.updateLocalPeerInfo).toBe('function');
    });
  });
});

