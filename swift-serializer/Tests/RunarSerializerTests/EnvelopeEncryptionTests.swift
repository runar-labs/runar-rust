import XCTest
@testable import RunarSerializer

final class EnvelopeEncryptionTests: XCTestCase {
    
    func testEnvelopeEncryptedDataCreation() {
        let encryptedData = Data([1, 2, 3, 4])
        let networkId = "test-network"
        let networkEncryptedKey = Data([5, 6, 7, 8])
        let profileEncryptedKeys = ["profile1": Data([9, 10]), "profile2": Data([11, 12])]
        
        let envelopeData = EnvelopeEncryptedData(
            encryptedData: encryptedData,
            networkId: networkId,
            networkEncryptedKey: networkEncryptedKey,
            profileEncryptedKeys: profileEncryptedKeys
        )
        
        XCTAssertEqual(envelopeData.encryptedData, encryptedData)
        XCTAssertEqual(envelopeData.networkId, networkId)
        XCTAssertEqual(envelopeData.networkEncryptedKey, networkEncryptedKey)
        XCTAssertEqual(envelopeData.profileEncryptedKeys.count, 2)
        XCTAssertEqual(envelopeData.profileEncryptedKeys["profile1"], Data([9, 10]))
        XCTAssertEqual(envelopeData.profileEncryptedKeys["profile2"], Data([11, 12]))
    }
    
    func testEnvelopeEncryptedDataWithoutNetwork() {
        let encryptedData = Data([1, 2, 3, 4])
        let networkEncryptedKey = Data([5, 6, 7, 8])
        let profileEncryptedKeys = ["profile1": Data([9, 10])]
        
        let envelopeData = EnvelopeEncryptedData(
            encryptedData: encryptedData,
            networkId: nil,
            networkEncryptedKey: networkEncryptedKey,
            profileEncryptedKeys: profileEncryptedKeys
        )
        
        XCTAssertEqual(envelopeData.encryptedData, encryptedData)
        XCTAssertNil(envelopeData.networkId)
        XCTAssertEqual(envelopeData.networkEncryptedKey, networkEncryptedKey)
        XCTAssertEqual(envelopeData.profileEncryptedKeys.count, 1)
    }
    
    func testSerializationContextWithEncryption() {
        let mockKeyManager = MockMobileKeyManager()
        let mockResolver = DefaultLabelResolver(labelToProfileId: ["user": "profile1"])
        
        let context = SerializationContext(
            keystore: MockKeyStore(),
            resolver: mockResolver,
            networkId: "test-network",
            profileId: "profile1",
            mobileKeyManager: mockKeyManager,
            profileIds: ["profile1", "profile2"]
        )
        
        XCTAssertNotNil(context.mobileKeyManager)
        XCTAssertEqual(context.profileIds.count, 2)
        XCTAssertEqual(context.profileIds[0], "profile1")
        XCTAssertEqual(context.profileIds[1], "profile2")
        XCTAssertEqual(context.networkId, "test-network")
        XCTAssertEqual(context.profileId, "profile1")
    }
    
    func testDefaultLabelResolver() {
        let resolver = DefaultLabelResolver(labelToProfileId: [
            "user": "profile1",
            "work": "profile2",
            "family": "profile3"
        ])
        
        XCTAssertEqual(resolver.resolveLabel("user"), "profile1")
        XCTAssertEqual(resolver.resolveLabel("work"), "profile2")
        XCTAssertEqual(resolver.resolveLabel("family"), "profile3")
        XCTAssertNil(resolver.resolveLabel("unknown"))
    }
    
    func testEnvelopeEncryptionCBORSerialization() throws {
        let encryptedData = Data([1, 2, 3, 4])
        let networkId = "test-network"
        let networkEncryptedKey = Data([5, 6, 7, 8])
        let profileEncryptedKeys = ["profile1": Data([9, 10])]
        
        let envelopeData = EnvelopeEncryptedData(
            encryptedData: encryptedData,
            networkId: networkId,
            networkEncryptedKey: networkEncryptedKey,
            profileEncryptedKeys: profileEncryptedKeys
        )
        
        // Serialize to CBOR
        let serialized = try EnvelopeEncryption.serializeToCBOR(envelopeData)
        XCTAssertFalse(serialized.isEmpty)
        
        // Deserialize from CBOR
        let deserialized = try EnvelopeEncryption.deserializeFromCBOR(serialized)
        
        // Verify round-trip
        XCTAssertEqual(deserialized.encryptedData, encryptedData)
        XCTAssertEqual(deserialized.networkId, networkId)
        XCTAssertEqual(deserialized.networkEncryptedKey, networkEncryptedKey)
        XCTAssertEqual(deserialized.profileEncryptedKeys.count, 1)
        XCTAssertEqual(deserialized.profileEncryptedKeys["profile1"], Data([9, 10]))
    }
    
    func testEnvelopeEncryptionCBORSerializationWithoutNetwork() throws {
        let encryptedData = Data([1, 2, 3, 4])
        let networkEncryptedKey = Data([5, 6, 7, 8])
        let profileEncryptedKeys = ["profile1": Data([9, 10]), "profile2": Data([11, 12])]
        
        let envelopeData = EnvelopeEncryptedData(
            encryptedData: encryptedData,
            networkId: nil,
            networkEncryptedKey: networkEncryptedKey,
            profileEncryptedKeys: profileEncryptedKeys
        )
        
        // Serialize to CBOR
        let serialized = try EnvelopeEncryption.serializeToCBOR(envelopeData)
        XCTAssertFalse(serialized.isEmpty)
        
        // Deserialize from CBOR
        let deserialized = try EnvelopeEncryption.deserializeFromCBOR(serialized)
        
        // Verify round-trip
        XCTAssertEqual(deserialized.encryptedData, encryptedData)
        XCTAssertNil(deserialized.networkId)
        XCTAssertEqual(deserialized.networkEncryptedKey, networkEncryptedKey)
        XCTAssertEqual(deserialized.profileEncryptedKeys.count, 2)
        XCTAssertEqual(deserialized.profileEncryptedKeys["profile1"], Data([9, 10]))
        XCTAssertEqual(deserialized.profileEncryptedKeys["profile2"], Data([11, 12]))
    }
    
    func testEnvelopeEncryptionWithMockKeyManager() throws {
        let mockKeyManager = MockMobileKeyManager()
        let context = SerializationContext(
            keystore: MockKeyStore(),
            resolver: MockLabelResolver(),
            networkId: "test-network",
            profileId: "profile1",
            mobileKeyManager: mockKeyManager,
            profileIds: ["profile1"]
        )
        
        let testData = "Hello, encrypted world!".data(using: .utf8)!
        
        // Test encryption
        let encrypted = try EnvelopeEncryption.encrypt(testData, context: context)
        
        XCTAssertEqual(encrypted.encryptedData, mockKeyManager.lastEncryptedData)
        XCTAssertEqual(encrypted.networkId, "test-network")
        XCTAssertFalse(encrypted.networkEncryptedKey.isEmpty)
        XCTAssertEqual(encrypted.profileEncryptedKeys.count, 1)
        XCTAssertTrue(encrypted.profileEncryptedKeys.keys.contains("profile1"))
        
        // Test decryption
        let decrypted = try EnvelopeEncryption.decrypt(encrypted, context: context)
        XCTAssertEqual(decrypted, testData)
    }
    
    func testEnvelopeEncryptionWithProfileId() throws {
        let mockKeyManager = MockMobileKeyManager()
        let context = SerializationContext(
            keystore: MockKeyStore(),
            resolver: MockLabelResolver(),
            networkId: "test-network",
            profileId: "profile1",
            mobileKeyManager: mockKeyManager,
            profileIds: ["profile1", "profile2"]
        )
        
        let testData = "Profile-specific encryption".data(using: .utf8)!
        
        // Test encryption
        let encrypted = try EnvelopeEncryption.encrypt(testData, context: context)
        
        // Test decryption with specific profile
        let decrypted = try EnvelopeEncryption.decrypt(encrypted, context: context, profileId: "profile1")
        XCTAssertEqual(decrypted, testData)
    }
    
    func testEnvelopeEncryptionNoKeyManager() {
        let context = SerializationContext(
            keystore: MockKeyStore(),
            resolver: MockLabelResolver(),
            networkId: "test-network",
            profileId: "profile1"
        )
        
        let testData = "Hello, world!".data(using: .utf8)!
        
        // Should throw error when no key manager is provided
        XCTAssertThrowsError(try EnvelopeEncryption.encrypt(testData, context: context)) { error in
            XCTAssertTrue(error is SerializerError)
            let errorMessage = (error as? SerializerError)?.localizedDescription ?? ""
            XCTAssertTrue(errorMessage.contains("No key manager provided"))
        }
    }
    
    func testInvalidCBORDeserialization() {
        let invalidData = Data([0xFF, 0xFE, 0xFD]) // Invalid CBOR
        
        XCTAssertThrowsError(try EnvelopeEncryption.deserializeFromCBOR(invalidData)) { error in
            XCTAssertTrue(error is SerializerError)
            let errorMessage = (error as? SerializerError)?.localizedDescription ?? ""
            XCTAssertTrue(errorMessage.contains("Failed to decode CBOR") || errorMessage.contains("Deserialization failed"))
        }
    }
    
    static let allTests = [
        ("testEnvelopeEncryptedDataCreation", testEnvelopeEncryptedDataCreation),
        ("testEnvelopeEncryptedDataWithoutNetwork", testEnvelopeEncryptedDataWithoutNetwork),
        ("testSerializationContextWithEncryption", testSerializationContextWithEncryption),
        ("testDefaultLabelResolver", testDefaultLabelResolver),
        ("testEnvelopeEncryptionCBORSerialization", testEnvelopeEncryptionCBORSerialization),
        ("testEnvelopeEncryptionCBORSerializationWithoutNetwork", testEnvelopeEncryptionCBORSerializationWithoutNetwork),
        ("testEnvelopeEncryptionWithMockKeyManager", testEnvelopeEncryptionWithMockKeyManager),
        ("testEnvelopeEncryptionWithProfileId", testEnvelopeEncryptionWithProfileId),
        ("testEnvelopeEncryptionNoKeyManager", testEnvelopeEncryptionNoKeyManager),
        ("testInvalidCBORDeserialization", testInvalidCBORDeserialization)
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