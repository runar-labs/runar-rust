import XCTest
@testable import RunarSerializer
import SwiftCBOR

final class CBORTests: XCTestCase {
    
    func testCBORStringEncoding() {
        let testString = "Hello, World!"
        
        let encoded = testString.encode()
        // CBOR text string format: [0x60 + length][bytes] for short strings
        XCTAssertGreaterThan(encoded.count, testString.count)
        XCTAssertEqual(encoded[0], 0x60 + UInt8(testString.count))
    }
    
    func testCBORIntEncoding() {
        let testInt = 42
        
        let encoded = testInt.encode()
        // CBOR unsigned integer format: [0x18][byte] for integers 24-255
        XCTAssertEqual(encoded.count, 2)
        XCTAssertEqual(encoded[0], 0x18) // 1-byte length indicator
        XCTAssertEqual(encoded[1], UInt8(testInt))
    }
    
    func testCBORBoolEncoding() {
        let trueEncoded = true.encode()
        XCTAssertEqual(trueEncoded, [0xF5]) // CBOR true
        
        let falseEncoded = false.encode()
        XCTAssertEqual(falseEncoded, [0xF4]) // CBOR false
    }
    
    func testCBORBytesEncoding() {
        let testData = "Test bytes".data(using: .utf8)!
        
        let encoded = Array(testData).encode()
        // CBOR byte string format: [0x40 + length][bytes] for short byte strings
        XCTAssertGreaterThan(encoded.count, testData.count)
        // Just verify it's a valid CBOR encoding
        XCTAssertGreaterThan(encoded.count, 0)
    }
    
    func testAnyValueBinaryFormat() {
        let testString = "Test"
        let primitiveValue = AnyValue.primitive(testString)
        
        do {
            let serialized = try primitiveValue.serialize()
            
            // Verify binary format: [category][encrypted][type_name_len][type_name][cbor_data]
            XCTAssertGreaterThanOrEqual(serialized.count, 4)
            
            let category = serialized[0]
            XCTAssertEqual(category, ValueCategory.primitive.rawValue)
            
            let encrypted = serialized[1]
            XCTAssertEqual(encrypted, 0x00) // Not encrypted
            
            let typeNameLen = serialized[2]
            XCTAssertGreaterThan(typeNameLen, 0)
            
            // Verify type name
            let typeNameData = serialized[3..<(3 + Int(typeNameLen))]
            let typeName = String(data: Data(typeNameData), encoding: .utf8)!
            XCTAssertEqual(typeName, "String")
            
            // Verify CBOR data follows
            let cborData = serialized[(3 + Int(typeNameLen))...]
            XCTAssertGreaterThan(cborData.count, 0)
            
        } catch {
            XCTFail("Failed to serialize AnyValue: \(error)")
        }
    }
    
    func testAnyValueDeserialization() async {
        let testData = "Test bytes".data(using: .utf8)!
        let bytesValue = AnyValue.bytes(testData)
        
        do {
            let serialized = try bytesValue.serialize()
            let deserialized = try AnyValue.deserialize(serialized)
            
            XCTAssertEqual(deserialized.category, .bytes)
            let retrievedData: Data = try await deserialized.asType()
            XCTAssertEqual(retrievedData, testData)
            
        } catch {
            XCTFail("Failed to serialize/deserialize bytes: \(error)")
        }
    }
    
    static let allTests = [
        ("testCBORStringEncoding", testCBORStringEncoding),
        ("testCBORIntEncoding", testCBORIntEncoding),
        ("testCBORBoolEncoding", testCBORBoolEncoding),
        ("testCBORBytesEncoding", testCBORBytesEncoding),
        ("testAnyValueBinaryFormat", testAnyValueBinaryFormat),
        ("testAnyValueDeserialization", testAnyValueDeserialization),
    ]
} 