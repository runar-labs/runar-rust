import XCTest
import Foundation
import os.log
@testable import RunarTransporter

@available(macOS 12.0, iOS 15.0, *)
final class DiscoveryServiceTests: XCTestCase {
    
    private let logger = Logger(subsystem: "com.runar.transporter.tests", category: "discovery")
    
    // MARK: - Test Properties
    
    private var discoveryService1: DiscoveryService?
    private var discoveryService2: DiscoveryService?
    private var discoveredPeers1: [RunarPeerInfo] = []
    private var discoveredPeers2: [RunarPeerInfo] = []
    private var lostPeers1: [String] = []
    private var lostPeers2: [String] = []
    
    // MARK: - Test Setup
    
    override func setUp() async throws {
        try await super.setUp()
        
        // Create test node info
        let node1Key = Data(repeating: 0x01, count: 32)
        let node2Key = Data(repeating: 0x02, count: 32)
        
        let node1Info = RunarNodeInfo(
            nodePublicKey: node1Key,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8080"],
            services: []
        )
        
        let node2Info = RunarNodeInfo(
            nodePublicKey: node2Key,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8081"],
            services: []
        )
        
        // Create discovery services with different multicast ports to avoid conflicts
        discoveryService1 = DiscoveryService(
            nodeInfo: node1Info,
            multicastGroup: "224.0.0.1",
            multicastPort: 8082,
            logger: logger
        )
        
        discoveryService2 = DiscoveryService(
            nodeInfo: node2Info,
            multicastGroup: "224.0.0.1",
            multicastPort: 8082,
            logger: logger
        )
        
        // Set up callbacks
        discoveryService1?.onPeerDiscovered { [weak self] peerInfo in
            self?.discoveredPeers1.append(peerInfo)
        }
        
        discoveryService1?.onPeerLost { [weak self] peerId in
            self?.lostPeers1.append(peerId)
        }
        
        discoveryService2?.onPeerDiscovered { [weak self] peerInfo in
            self?.discoveredPeers2.append(peerInfo)
        }
        
        discoveryService2?.onPeerLost { [weak self] peerId in
            self?.lostPeers2.append(peerId)
        }
    }
    
    override func tearDown() async throws {
        // Stop discovery services
        await discoveryService1?.stop()
        await discoveryService2?.stop()
        
        discoveryService1 = nil
        discoveryService2 = nil
        discoveredPeers1.removeAll()
        discoveredPeers2.removeAll()
        lostPeers1.removeAll()
        lostPeers2.removeAll()
        
        try await super.tearDown()
    }
    
    // MARK: - Tests
    
    func testDiscoveryServiceCreation() {
        XCTAssertNotNil(discoveryService1)
        XCTAssertNotNil(discoveryService2)
    }
    
    func testDiscoveryServiceStartStop() async throws {
        // Test starting discovery service
        try await discoveryService1?.start()
        
        // Verify service is running
        let peers = discoveryService1?.getDiscoveredPeers() ?? []
        XCTAssertEqual(peers.count, 0, "Should start with no discovered peers")
        
        // Test stopping discovery service
        await discoveryService1?.stop()
        
        // Verify service is stopped
        let peersAfterStop = discoveryService1?.getDiscoveredPeers() ?? []
        XCTAssertEqual(peersAfterStop.count, 0, "Should have no peers after stopping")
    }
    
    func testPeerDiscovery() async throws {
        // Start both discovery services
        try await discoveryService1?.start()
        try await discoveryService2?.start()
        
        // Wait for discovery to occur
        try await Task.sleep(nanoseconds: 3_000_000_000) // 3 seconds
        
        // Verify peers were discovered
        let peers1 = discoveryService1?.getDiscoveredPeers() ?? []
        let peers2 = discoveryService2?.getDiscoveredPeers() ?? []
        
        XCTAssertGreaterThanOrEqual(peers1.count, 1, "Service 1 should discover at least one peer")
        XCTAssertGreaterThanOrEqual(peers2.count, 1, "Service 2 should discover at least one peer")
        
        // Verify callback was called
        XCTAssertGreaterThanOrEqual(discoveredPeers1.count, 1, "Discovery callback should be called for service 1")
        XCTAssertGreaterThanOrEqual(discoveredPeers2.count, 1, "Discovery callback should be called for service 2")
        
        // Verify discovered peer info
        if let peer1 = peers1.first {
            XCTAssertEqual(peer1.addresses.count, 1, "Peer should have one address")
            XCTAssertEqual(peer1.addresses.first, "127.0.0.1:8081", "Peer address should match")
        }
        
        if let peer2 = peers2.first {
            XCTAssertEqual(peer2.addresses.count, 1, "Peer should have one address")
            XCTAssertEqual(peer2.addresses.first, "127.0.0.1:8080", "Peer address should match")
        }
    }
    
    func testPeerAnnouncement() async throws {
        // Start discovery service 1
        try await discoveryService1?.start()
        
        // Wait a bit
        try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
        
        // Manually announce service 2
        try await discoveryService2?.announce()
        
        // Wait for discovery
        try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
        
        // Verify peer was discovered
        let peers = discoveryService1?.getDiscoveredPeers() ?? []
        XCTAssertGreaterThanOrEqual(peers.count, 1, "Should discover announced peer")
        
        // Verify callback was called
        XCTAssertGreaterThanOrEqual(discoveredPeers1.count, 1, "Discovery callback should be called")
    }
    
    func testPeerLoss() async throws {
        // Start both discovery services
        try await discoveryService1?.start()
        try await discoveryService2?.start()
        
        // Wait for discovery
        try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
        
        // Stop service 2 (simulate peer leaving)
        await discoveryService2?.stop()
        
        // Wait for goodbye message
        try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
        
        // Verify peer loss callback was called
        XCTAssertGreaterThanOrEqual(lostPeers1.count, 1, "Peer loss callback should be called")
    }
    
    func testMultiplePeers() async throws {
        // Create a third discovery service
        let node3Key = Data(repeating: 0x03, count: 32)
        let node3Info = RunarNodeInfo(
            nodePublicKey: node3Key,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8083"],
            services: []
        )
        
        let discoveryService3 = DiscoveryService(
            nodeInfo: node3Info,
            multicastGroup: "224.0.0.1",
            multicastPort: 8082,
            logger: logger
        )
        
        var discoveredPeers3: [RunarPeerInfo] = []
        discoveryService3.onPeerDiscovered { peerInfo in
            discoveredPeers3.append(peerInfo)
        }
        
        // Start all three services
        try await discoveryService1?.start()
        try await discoveryService2?.start()
        try await discoveryService3.start()
        
        // Wait for discovery
        try await Task.sleep(nanoseconds: 4_000_000_000) // 4 seconds
        
        // Verify each service discovered the other two
        let peers1 = discoveryService1?.getDiscoveredPeers() ?? []
        let peers2 = discoveryService2?.getDiscoveredPeers() ?? []
        let peers3 = discoveryService3.getDiscoveredPeers()
        
        XCTAssertGreaterThanOrEqual(peers1.count, 2, "Service 1 should discover 2 peers")
        XCTAssertGreaterThanOrEqual(peers2.count, 2, "Service 2 should discover 2 peers")
        XCTAssertGreaterThanOrEqual(peers3.count, 2, "Service 3 should discover 2 peers")
        
        // Clean up
        await discoveryService3.stop()
    }
    
    func testDiscoveryServiceWithCustomMulticastGroup() async throws {
        // Create discovery service with custom multicast group
        let nodeKey = Data(repeating: 0x04, count: 32)
        let nodeInfo = RunarNodeInfo(
            nodePublicKey: nodeKey,
            networkIds: ["test-network"],
            addresses: ["127.0.0.1:8084"],
            services: []
        )
        
        let customDiscoveryService = DiscoveryService(
            nodeInfo: nodeInfo,
            multicastGroup: "224.0.0.100",
            multicastPort: 8085,
            logger: logger
        )
        
        // Test starting with custom group
        try await customDiscoveryService.start()
        
        // Wait a bit
        try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
        
        // Verify service started successfully
        let peers = customDiscoveryService.getDiscoveredPeers()
        XCTAssertEqual(peers.count, 0, "Should have no peers on custom multicast group")
        
        // Clean up
        await customDiscoveryService.stop()
    }
    
    func testDiscoveryServiceErrorHandling() async throws {
        // Test starting discovery service without proper network setup
        // This might fail on some systems, so we'll just test that it doesn't crash
        let invalidDiscoveryService = DiscoveryService(
            nodeInfo: RunarNodeInfo(
                nodePublicKey: Data(repeating: 0x05, count: 32),
                networkIds: ["test-network"],
                addresses: ["127.0.0.1:8086"],
                services: []
            ),
            multicastGroup: "invalid-group",
            multicastPort: 8087,
            logger: logger
        )
        
        // Try to start - should not crash
        do {
            try await invalidDiscoveryService.start()
            // If it starts successfully, stop it
            await invalidDiscoveryService.stop()
        } catch {
            // Expected to fail on some systems
            logger.warning("Discovery service failed to start (expected on some systems): \(error)")
        }
    }
    
    func testDiscoveryServicePerformance() async throws {
        // Test performance of discovery operations
        try await discoveryService1?.start()
        
        measure {
            // Measure the performance of getting discovered peers
            for _ in 0..<100 {
                _ = discoveryService1?.getDiscoveredPeers() ?? []
            }
        }
    }
    
    func testDiscoveryServiceConcurrentOperations() async throws {
        // Test concurrent operations on discovery service
        try await discoveryService1?.start()
        
        // Perform concurrent operations
        await withTaskGroup(of: Void.self) { group in
            // Task 1: Get discovered peers
            group.addTask {
                for _ in 0..<10 {
                    _ = self.discoveryService1?.getDiscoveredPeers() ?? []
                    try? await Task.sleep(nanoseconds: 100_000_000) // 0.1 seconds
                }
            }
            
            // Task 2: Announce
            group.addTask {
                for _ in 0..<5 {
                    try? await self.discoveryService1?.announce()
                    try? await Task.sleep(nanoseconds: 200_000_000) // 0.2 seconds
                }
            }
        }
        
        // Verify no crashes occurred
        XCTAssertNotNil(discoveryService1, "Discovery service should still exist")
    }
} 