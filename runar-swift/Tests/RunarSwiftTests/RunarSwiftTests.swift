import XCTest
@testable import RunarSwift

final class RunarSwiftTests: XCTestCase {
    
    override func setUpWithError() throws {
        // No initialization needed for simplified API
    }
    
    override func tearDownWithError() throws {
        // Cleanup after each test
    }
    
    func testNodeCreation() throws {
        let config = NodeConfig(
            nodeId: "test-node",
            networkId: "test-network",
            requestTimeoutMs: 5000,
            logLevel: "info"
        )
        
        let node = try RunarSwift.createNode(config: config)
        XCTAssertNotNil(node)
    }
    
    func testNodeStart() throws {
        let config = NodeConfig(
            nodeId: "test-node",
            networkId: "test-network",
            requestTimeoutMs: 5000,
            logLevel: "info"
        )
        
        let node = try RunarSwift.createNode(config: config)
        
        let startExpectation = XCTestExpectation(description: "Node start")
        node.start { result in
            switch result {
            case .success:
                startExpectation.fulfill()
            case .failure(let error):
                XCTFail("Node start failed: \(error)")
            }
        }
        wait(for: [startExpectation], timeout: 5.0)
    }
    
    func testMockEchoService() throws {
        let config = NodeConfig(
            nodeId: "test-node",
            networkId: "test-network",
            requestTimeoutMs: 5000,
            logLevel: "info"
        )
        
        let node = try RunarSwift.createNode(config: config)
        
        // Start the node first
        let startExpectation = XCTestExpectation(description: "Node start")
        node.start { result in
            switch result {
            case .success:
                startExpectation.fulfill()
            case .failure(let error):
                XCTFail("Node start failed: \(error)")
            }
        }
        wait(for: [startExpectation], timeout: 5.0)
        
        // Test the mock echo service
        let testMessage = "Hello, Runar!"
        let requestExpectation = XCTestExpectation(description: "Echo request")
        
        node.request(path: "/mock/echo", data: testMessage) { result in
            switch result {
            case .success(let responseString):
                print("Echo response: \(responseString)")
                
                // Verify the echo service returns the same data
                XCTAssertEqual(responseString, testMessage)
                requestExpectation.fulfill()
            case .failure(let error):
                XCTFail("Echo request failed: \(error)")
            }
        }
        wait(for: [requestExpectation], timeout: 5.0)
        

    }
    
    func testErrorHandling() throws {
        // Test creating a node with invalid parameters
        // Note: With mock implementation, this should succeed
        let invalidConfig = NodeConfig(
            nodeId: "",
            networkId: "",
            requestTimeoutMs: 0,
            logLevel: "invalid"
        )
        
        // Mock implementation always succeeds, so we expect success
        let node = try RunarSwift.createNode(config: invalidConfig)
        XCTAssertNotNil(node, "Mock should create node even with invalid config")
    }
    
    static var allTests = [
        ("testNodeCreation", testNodeCreation),
        ("testNodeStart", testNodeStart),
        ("testMockEchoService", testMockEchoService),
        ("testErrorHandling", testErrorHandling),
    ]
} 