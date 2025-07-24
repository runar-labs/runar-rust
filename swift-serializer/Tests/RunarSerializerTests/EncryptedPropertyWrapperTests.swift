import XCTest
@testable import RunarSerializer

final class EncryptedPropertyWrapperTests: XCTestCase {
    
    func testEncryptedPropertyWrapperCreation() {
        let encrypted = EncryptedField<String>(label: "user")
        
        XCTAssertEqual(encrypted.encryptionLabel, "user")
        XCTAssertFalse(encrypted.hasValue)
        XCTAssertNil(encrypted.wrappedValue)
    }
    
    func testEncryptedPropertyWrapperWithValue() {
        var encrypted = EncryptedField<String>(label: "user")
        encrypted.wrappedValue = "secret data"
        
        XCTAssertEqual(encrypted.encryptionLabel, "user")
        XCTAssertTrue(encrypted.hasValue)
        XCTAssertEqual(encrypted.wrappedValue, "secret data")
    }
    
    func testStringEncryptable() throws {
        let testString = "Hello, encrypted world!"
        let data = try testString.toData()
        let decodedString = try String.fromData(data)
        
        XCTAssertEqual(decodedString, testString)
    }
    
    func testIntEncryptable() throws {
        let testInt = 42
        let data = try testInt.toData()
        let decodedInt = try Int.fromData(data)
        
        XCTAssertEqual(decodedInt, testInt)
    }
    
    func testBoolEncryptable() throws {
        let testBool = true
        let data = try testBool.toData()
        let decodedBool = try Bool.fromData(data)
        
        XCTAssertEqual(decodedBool, testBool)
        
        let testBoolFalse = false
        let dataFalse = try testBoolFalse.toData()
        let decodedBoolFalse = try Bool.fromData(dataFalse)
        
        XCTAssertEqual(decodedBoolFalse, testBoolFalse)
    }
    
    func testDoubleEncryptable() throws {
        let testDouble = 3.14159
        let data = try testDouble.toData()
        let decodedDouble = try Double.fromData(data)
        
        XCTAssertEqual(decodedDouble, testDouble, accuracy: 0.000001)
    }
    
    func testArrayEncryptable() throws {
        let testArray = ["one", "two", "three"]
        let data = try testArray.toData()
        let decodedArray = try [String].fromData(data)
        
        XCTAssertEqual(decodedArray, testArray)
    }
    
    func testDictionaryEncryptable() throws {
        let testDict = ["key1": "value1", "key2": "value2"]
        let data = try testDict.toData()
        let decodedDict = try [String: String].fromData(data)
        
        XCTAssertEqual(decodedDict, testDict)
    }
    
    func testEncryptedFieldUtilsWithMockKeyManager() throws {
        let mockKeyManager = MockMobileKeyManager()
        let context = SerializationContext(
            keystore: MockKeyStore(),
            resolver: MockLabelResolver(),
            networkId: "test-network",
            profileId: "profile1",
            mobileKeyManager: mockKeyManager,
            profileIds: ["profile1"]
        )
        
        var encryptedField = EncryptedField<String>(label: "user")
        encryptedField.wrappedValue = "secret message"
        
        // Test encryption
        let envelopeData = try EncryptedFieldUtils.encryptField(encryptedField, context: context)
        
        XCTAssertNotNil(envelopeData)
        XCTAssertEqual(envelopeData?.encryptedData, mockKeyManager.lastEncryptedData)
        XCTAssertEqual(envelopeData?.networkId, "test-network")
        
        // Test decryption
        let decryptedValue = try EncryptedFieldUtils.decryptField(
            envelopeData!,
            context: context,
            as: String.self
        )
        
        XCTAssertEqual(decryptedValue, "secret message")
    }
    
    func testEncryptedFieldUtilsWithNilValue() throws {
        let mockKeyManager = MockMobileKeyManager()
        let context = SerializationContext(
            keystore: MockKeyStore(),
            resolver: MockLabelResolver(),
            networkId: "test-network",
            profileId: "profile1",
            mobileKeyManager: mockKeyManager,
            profileIds: ["profile1"]
        )
        
        let encryptedField = EncryptedField<String>(label: "user")
        // No value set, so wrappedValue is nil
        
        // Test encryption with nil value
        let envelopeData = try EncryptedFieldUtils.encryptField(encryptedField, context: context)
        
        XCTAssertNil(envelopeData) // Should return nil when no value to encrypt
    }
    
    func testEncryptedFieldUtilsWithComplexTypes() throws {
        let mockKeyManager = MockMobileKeyManager()
        let context = SerializationContext(
            keystore: MockKeyStore(),
            resolver: MockLabelResolver(),
            networkId: "test-network",
            profileId: "profile1",
            mobileKeyManager: mockKeyManager,
            profileIds: ["profile1"]
        )
        
        var encryptedField = EncryptedField<[String: [Int]]>(label: "user")
        encryptedField.wrappedValue = ["scores": [100, 95, 87], "ages": [25, 30, 35]]
        
        // Test encryption
        let envelopeData = try EncryptedFieldUtils.encryptField(encryptedField, context: context)
        
        XCTAssertNotNil(envelopeData)
        
        // Test decryption
        let decryptedValue = try EncryptedFieldUtils.decryptField(
            envelopeData!,
            context: context,
            as: [String: [Int]].self
        )
        
        XCTAssertEqual(decryptedValue, ["scores": [100, 95, 87], "ages": [25, 30, 35]])
    }
    
    func testEncryptableErrorHandling() {
        // Test invalid data size for Int
        let invalidData = Data([1, 2, 3]) // Only 3 bytes, need 8 for Int
        
        XCTAssertThrowsError(try Int.fromData(invalidData)) { error in
            XCTAssertTrue(error is SerializerError)
            let errorMessage = (error as? SerializerError)?.localizedDescription ?? ""
            XCTAssertTrue(errorMessage.contains("Invalid data size"))
        }
        
        // Test invalid data size for Bool
        let invalidBoolData = Data([1, 2]) // 2 bytes, need 1 for Bool
        
        XCTAssertThrowsError(try Bool.fromData(invalidBoolData)) { error in
            XCTAssertTrue(error is SerializerError)
            let errorMessage = (error as? SerializerError)?.localizedDescription ?? ""
            XCTAssertTrue(errorMessage.contains("Invalid data size"))
        }
    }
    
    static let allTests = [
        ("testEncryptedPropertyWrapperCreation", testEncryptedPropertyWrapperCreation),
        ("testEncryptedPropertyWrapperWithValue", testEncryptedPropertyWrapperWithValue),
        ("testStringEncryptable", testStringEncryptable),
        ("testIntEncryptable", testIntEncryptable),
        ("testBoolEncryptable", testBoolEncryptable),
        ("testDoubleEncryptable", testDoubleEncryptable),
        ("testArrayEncryptable", testArrayEncryptable),
        ("testDictionaryEncryptable", testDictionaryEncryptable),
        ("testEncryptedFieldUtilsWithMockKeyManager", testEncryptedFieldUtilsWithMockKeyManager),
        ("testEncryptedFieldUtilsWithNilValue", testEncryptedFieldUtilsWithNilValue),
        ("testEncryptedFieldUtilsWithComplexTypes", testEncryptedFieldUtilsWithComplexTypes),
        ("testEncryptableErrorHandling", testEncryptableErrorHandling)
    ]
}

// MARK: - Mock Types for Testing

private class MockKeyStore: KeyStore {
    // Mock implementation
}

private class MockLabelResolver: LabelResolver {
    func resolveLabel(_ label: String) -> String? {
        return label == "user" ? "profile1" : nil
    }
}

private class MockMobileKeyManager: MobileKeyManager {
    var lastEncryptedData: Data = Data()
    var shouldThrowError = false
    
    func encryptWithEnvelope(
        data: Data,
        networkId: String?,
        profileIds: [String]
    ) throws -> EnvelopeEncryptedData {
        if shouldThrowError {
            throw SerializerError.encryptionFailed("Mock encryption error")
        }
        
        lastEncryptedData = data
        
        // Create a mock envelope with the original data as "encrypted" data
        return EnvelopeEncryptedData(
            encryptedData: data,
            networkId: networkId,
            networkEncryptedKey: Data([1, 2, 3, 4]),
            profileEncryptedKeys: Dictionary(uniqueKeysWithValues: profileIds.map { ($0, Data([5, 6, 7, 8])) })
        )
    }
    
    func decryptWithProfile(
        envelopeData: EnvelopeEncryptedData,
        profileId: String
    ) throws -> Data {
        if shouldThrowError {
            throw SerializerError.encryptionFailed("Mock decryption error")
        }
        
        // Return the "encrypted" data as the decrypted data (for testing)
        return envelopeData.encryptedData
    }
    
    func decryptWithNetwork(
        envelopeData: EnvelopeEncryptedData
    ) throws -> Data {
        if shouldThrowError {
            throw SerializerError.encryptionFailed("Mock decryption error")
        }
        
        // Return the "encrypted" data as the decrypted data (for testing)
        return envelopeData.encryptedData
    }
} 