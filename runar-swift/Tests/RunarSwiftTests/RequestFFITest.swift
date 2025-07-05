import XCTest
@testable import RunarSwift

final class RequestFFITest: XCTestCase {
    func testRequestEcho() throws {
        let config = RunarSwift.createTestConfig()
        let node = try RunarSwift.createNode(config: config)
        let expectation = self.expectation(description: "Async request")
        let testPayload = "{\"msg\":\"hello ffi\"}"
        
        node.request(path: "/mock/echo", data: testPayload) { result in
            switch result {
            case .success(let response):
                XCTAssertEqual(response, testPayload, "Echoed response should match request payload")
            case .failure(let error):
                XCTFail("Request failed: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 2.0)
    }
    
    func testDirectFFICall() throws {
        // Test direct FFI call to verify the function is accessible
        let testData = "Hello, FFI!"
        let testDataLen = UInt(testData.utf8.count)
        
        // Create a simple callback that just prints
        let callback: @convention(c) (UnsafePointer<Int8>, UInt, UnsafePointer<Int8>?) -> Void = { data, len, error in
            print("Direct FFI callback called with len: \(len)")
            let dataStr = String(cString: data)
            print("Direct FFI callback data: '\(dataStr)'")
        }
        
        // Call the Rust function directly with proper pointer lifetime
        print("Calling runar_node_request directly...")
        testData.withCString { testDataCString in
            "/test".withCString { pathCString in
                runar_node_request(
                    UnsafeMutableRawPointer(bitPattern: 0x1234)!, // Dummy node pointer
                    pathCString,
                    testDataCString,
                    testDataLen,
                    callback
                )
            }
        }
        print("Direct FFI call completed")
    }
} 