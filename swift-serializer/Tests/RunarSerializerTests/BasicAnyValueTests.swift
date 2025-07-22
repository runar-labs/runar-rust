import XCTest
@testable import RunarSerializer

final class BasicAnyValueTests: XCTestCase {
    
    func testNullValue() {
        let nullValue = AnyValue.null()
        
        XCTAssertTrue(nullValue.isNull)
        XCTAssertEqual(nullValue.category, .null)
        XCTAssertEqual(nullValue.typeName, "null")
        
        // Test serialization
        do {
            let serialized = try nullValue.serialize()
            XCTAssertEqual(serialized.count, 1)
            XCTAssertEqual(serialized[0], 0) // null category byte
        } catch {
            XCTFail("Failed to serialize null value: \(error)")
        }
    }
    
    func testPrimitiveString() async {
        let testString = "Hello, World!"
        let primitiveValue = AnyValue.primitive(testString)
        
        XCTAssertFalse(primitiveValue.isNull)
        XCTAssertEqual(primitiveValue.category, .primitive)
        XCTAssertEqual(primitiveValue.typeName, "String")
        
        // Test type retrieval
        do {
            let retrievedString: String = try await primitiveValue.asType()
            XCTAssertEqual(retrievedString, testString)
        } catch {
            XCTFail("Failed to get string value: \(error)")
        }
        
        // Test serialization
        do {
            let serialized = try primitiveValue.serialize()
            XCTAssertFalse(serialized.isEmpty)
        } catch {
            XCTFail("Failed to serialize primitive value: \(error)")
        }
    }
    
    func testBytesValue() async {
        let testData = "Test bytes".data(using: .utf8)!
        let bytesValue = AnyValue.bytes(testData)
        
        XCTAssertFalse(bytesValue.isNull)
        XCTAssertEqual(bytesValue.category, .bytes)
        XCTAssertEqual(bytesValue.typeName, "Data")
        
        // Test type retrieval
        do {
            let retrievedData: Data = try await bytesValue.asType()
            XCTAssertEqual(retrievedData, testData)
        } catch {
            XCTFail("Failed to get bytes value: \(error)")
        }
        
        // Test serialization
        do {
            let serialized = try bytesValue.serialize()
            // The new format includes: [category][encrypted][type_name_len][type_name][data]
            // For bytes: [5][0][4]["Data"][actual_data]
            XCTAssertGreaterThan(serialized.count, testData.count)
            // Verify the data is at the end
            let dataStart = 3 + 4 // category + encrypted + type_name_len + "Data"
            let actualData = serialized[dataStart...]
            XCTAssertEqual(Data(actualData), testData)
        } catch {
            XCTFail("Failed to serialize bytes value: \(error)")
        }
    }
    
    func testTypeMismatch() async {
        let testString = "Hello"
        let primitiveValue = AnyValue.primitive(testString)
        
        // Try to get as wrong type
        do {
            let _: Data = try await primitiveValue.asType()
            XCTFail("Should have thrown type mismatch error")
        } catch SerializerError.typeMismatch {
            // Expected error
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testDeserializeNull() {
        let nullData = Data([0]) // null category byte
        
        do {
            let deserialized = try AnyValue.deserialize(nullData)
            XCTAssertTrue(deserialized.isNull)
            XCTAssertEqual(deserialized.category, .null)
        } catch {
            XCTFail("Failed to deserialize null: \(error)")
        }
    }
    
    func testDeserializeEmptyData() {
        let emptyData = Data()
        
        do {
            let _ = try AnyValue.deserialize(emptyData)
            XCTFail("Should have thrown empty data error")
        } catch SerializerError.emptyData {
            // Expected error
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testDeserializeInvalidCategory() {
        let invalidData = Data([255]) // Invalid category byte
        
        do {
            let _ = try AnyValue.deserialize(invalidData)
            XCTFail("Should have thrown invalid category error")
        } catch SerializerError.invalidCategory(255) {
            // Expected error
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testValueCategoryFromRaw() {
        XCTAssertEqual(ValueCategory.from(0), .null)
        XCTAssertEqual(ValueCategory.from(1), .primitive)
        XCTAssertEqual(ValueCategory.from(2), .list)
        XCTAssertEqual(ValueCategory.from(3), .map)
        XCTAssertEqual(ValueCategory.from(4), .struct)
        XCTAssertEqual(ValueCategory.from(5), .bytes)
        XCTAssertEqual(ValueCategory.from(6), .json)
        XCTAssertNil(ValueCategory.from(255))
    }
    
    static let allTests = [
        ("testNullValue", testNullValue),
        ("testPrimitiveString", testPrimitiveString),
        ("testBytesValue", testBytesValue),
        ("testTypeMismatch", testTypeMismatch),
        ("testDeserializeNull", testDeserializeNull),
        ("testDeserializeEmptyData", testDeserializeEmptyData),
        ("testDeserializeInvalidCategory", testDeserializeInvalidCategory),
        ("testValueCategoryFromRaw", testValueCategoryFromRaw),
    ]
} 