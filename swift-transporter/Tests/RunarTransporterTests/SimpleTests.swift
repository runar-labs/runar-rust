import XCTest
import Logging
@testable import RunarTransporter

final class SimpleTests: XCTestCase {
    var logger: Logger!
    
    override func setUp() {
        super.setUp()
        logger = Logger(label: "test")
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testCreateSimpleTransporter() throws {
        let publicKey = Data("test-node-public-key".utf8)
        let nodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey),
            nodePublicKey: publicKey,
            nodeName: "TestNode",
            addresses: ["127.0.0.1:8080"],
            metadata: ["test": "value"],
            createdAt: Date()
        )
        
        let transporter = RunarTransporter.createSimpleTransporter(
            nodeInfo: nodeInfo,
            logger: logger
        )
        
        XCTAssertNotNil(transporter)
        XCTAssertEqual(transporter.localAddress, "127.0.0.1:0")
    }
    
    func testCreateBasicTransporter() throws {
        let publicKey = Data("test-node-public-key".utf8)
        let nodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey),
            nodePublicKey: publicKey,
            nodeName: "TestNode",
            addresses: ["127.0.0.1:8080"],
            metadata: ["test": "value"],
            createdAt: Date()
        )
        
        let transporter = RunarTransporter.createBasicTransporter(
            nodeInfo: nodeInfo,
            logger: logger
        )
        
        XCTAssertNotNil(transporter)
        XCTAssertEqual(transporter.localAddress, "127.0.0.1:8080")
    }
    
    func testCreateQuicTransporter() throws {
        let publicKey = Data("test-node-public-key".utf8)
        let nodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey),
            nodePublicKey: publicKey,
            nodeName: "TestNode",
            addresses: ["127.0.0.1:8080"],
            metadata: ["test": "value"],
            createdAt: Date()
        )
        
        let transporter = RunarTransporter.createQuicTransporter(
            nodeInfo: nodeInfo,
            logger: logger
        )
        
        XCTAssertNotNil(transporter)
        XCTAssertEqual(transporter.localAddress, "127.0.0.1:9090")
    }
    
    func testTransporterLifecycle() async throws {
        let publicKey = Data("test-node-public-key".utf8)
        let nodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey),
            nodePublicKey: publicKey,
            nodeName: "TestNode",
            addresses: ["127.0.0.1:8080"],
            metadata: ["test": "value"],
            createdAt: Date()
        )
        
        let transporter = RunarTransporter.createSimpleTransporter(
            nodeInfo: nodeInfo,
            logger: logger
        )
        
        // Test start
        try await transporter.start()
        
        // Test stop
        try await transporter.stop()
    }
    
    func testTransporterFactory() throws {
        let publicKey = Data("test-node-public-key".utf8)
        let nodeInfo = RunarNodeInfo(
            nodeId: NodeUtils.compactId(from: publicKey),
            nodePublicKey: publicKey,
            nodeName: "TestNode",
            addresses: ["127.0.0.1:8080"],
            metadata: ["test": "value"],
            createdAt: Date()
        )
        
        // Test factory with different types
        let simpleTransporter = TransportFactory.createTransporter(
            type: "simple",
            nodeInfo: nodeInfo,
            logger: logger
        )
        XCTAssertEqual(simpleTransporter.localAddress, "127.0.0.1:0")
        
        let basicTransporter = TransportFactory.createTransporter(
            type: "basic",
            nodeInfo: nodeInfo,
            logger: logger
        )
        XCTAssertEqual(basicTransporter.localAddress, "127.0.0.1:8080")
        
        let quicTransporter = TransportFactory.createTransporter(
            type: "quic",
            nodeInfo: nodeInfo,
            logger: logger
        )
        XCTAssertEqual(quicTransporter.localAddress, "127.0.0.1:9090")
        
        // Test unknown type defaults to simple
        let unknownTransporter = TransportFactory.createTransporter(
            type: "unknown",
            nodeInfo: nodeInfo,
            logger: logger
        )
        XCTAssertEqual(unknownTransporter.localAddress, "127.0.0.1:0")
    }
    
    func testLibraryVersion() {
        XCTAssertEqual(RunarTransporter.version, "1.0.0")
    }
} 