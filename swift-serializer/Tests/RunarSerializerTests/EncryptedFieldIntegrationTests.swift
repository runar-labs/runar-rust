import XCTest
@testable import RunarSerializer

final class EncryptedFieldIntegrationTests: XCTestCase {
    
    func testEncryptedFieldProtocolConformance() {
        var encryptedField = EncryptedField<String>(label: "user")
        encryptedField.wrappedValue = "test value"
        
        // Test protocol conformance
        XCTAssertTrue(encryptedField is EncryptedFieldProtocol)
        
        let protocolField = encryptedField as EncryptedFieldProtocol
        XCTAssertEqual(protocolField.encryptionLabel, "user")
        XCTAssertTrue(protocolField.hasValue)
    }
    
    func testEncryptedFieldWithoutValue() {
        let encryptedField = EncryptedField<String>(label: "user")
        // No value set
        
        let protocolField = encryptedField as EncryptedFieldProtocol
        XCTAssertEqual(protocolField.encryptionLabel, "user")
        XCTAssertFalse(protocolField.hasValue)
    }
    
    func testEncryptedFieldDetectionInStruct() {
        // Test that we can detect encrypted fields in a struct
        struct SimpleStruct {
            let regularField: String
            @EncryptedField(label: "user") var encryptedField: String?
        }
        
        var simple = SimpleStruct(regularField: "public data")
        simple.encryptedField = "secret data"
        
        // Test that the encrypted field is detected
        let mirror = Mirror(reflecting: simple)
        var hasEncryptedField = false
        
        for child in mirror.children {
            if let label = child.label {
                if child.value is EncryptedFieldProtocol {
                    hasEncryptedField = true
                    break
                }
            }
        }
        
        XCTAssertTrue(hasEncryptedField, "Should detect encrypted field in struct")
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
    
    static let allTests = [
        ("testEncryptedFieldProtocolConformance", testEncryptedFieldProtocolConformance),
        ("testEncryptedFieldWithoutValue", testEncryptedFieldWithoutValue),
        ("testEncryptedFieldDetectionInStruct", testEncryptedFieldDetectionInStruct),
        ("testEncryptedFieldUtilsWithMockKeyManager", testEncryptedFieldUtilsWithMockKeyManager)
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