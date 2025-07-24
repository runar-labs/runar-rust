import XCTest
import SwiftCBOR
@testable import RunarSerializer

/// Manual test struct that implements the encryption protocols without macros
struct ManualTestProfile: RunarEncryptable {
    let id: String
    var sensitive: String?
    var password: String?
    var apiKey: String?
    let publicInfo: String
    
    typealias Encrypted = ManualEncryptedTestProfile
    
    func encryptWithContext(_ context: Any?) throws -> ManualEncryptedTestProfile {
        guard let serializationContext = context as? SerializationContext else {
            throw SerializerError.encryptionFailed("Invalid serialization context")
        }
        
        var encryptedStruct = ManualEncryptedTestProfile()
        
        // Encrypt fields with label 'user'
        var userFields: [String: Any] = [:]
        if let value = self.sensitive {
            userFields["sensitive"] = value
        }
        if let value = self.password {
            userFields["password"] = value
        }
        
        if !userFields.isEmpty {
            let data = Data(try encodeToCBOR(userFields))
            let encryptionContext = SerializationContext(
                keystore: serializationContext.keystore,
                resolver: serializationContext.resolver,
                networkId: serializationContext.networkId,
                profileId: serializationContext.profileId,
                mobileKeyManager: serializationContext.mobileKeyManager,
                profileIds: [serializationContext.profileId]
            )
            encryptedStruct.encrypted_user = try EnvelopeEncryption.encrypt(data, context: encryptionContext)
        }
        
        // Encrypt fields with label 'system'
        var systemFields: [String: Any] = [:]
        if let value = self.apiKey {
            systemFields["apiKey"] = value
        }
        
        if !systemFields.isEmpty {
            let data = Data(try encodeToCBOR(systemFields))
            let encryptionContext = SerializationContext(
                keystore: serializationContext.keystore,
                resolver: serializationContext.resolver,
                networkId: serializationContext.networkId,
                profileId: serializationContext.profileId,
                mobileKeyManager: serializationContext.mobileKeyManager,
                profileIds: [serializationContext.profileId]
            )
            encryptedStruct.encrypted_system = try EnvelopeEncryption.encrypt(data, context: encryptionContext)
        }
        
        return encryptedStruct
    }
}

/// Manual encrypted struct that implements the decryption protocols without macros
struct ManualEncryptedTestProfile: RunarDecryptable {
    public var encrypted_user: EnvelopeEncryptedData?
    public var encrypted_system: EnvelopeEncryptedData?
    
    typealias Decrypted = ManualTestProfile
    
    func decryptWithContext(_ context: Any?) throws -> ManualTestProfile {
        guard let serializationContext = context as? SerializationContext else {
            throw SerializerError.encryptionFailed("Invalid serialization context")
        }
        
        var decryptedStruct = ManualTestProfile(
            id: "", // Will be set by caller
            sensitive: nil,
            password: nil,
            apiKey: nil,
            publicInfo: ""
        )
        
        // Decrypt fields with label 'user'
        if let encryptedData = self.encrypted_user {
            let decryptedData = try EnvelopeEncryption.decrypt(encryptedData, context: serializationContext)
            let cborData = Array(decryptedData)
            if let cbor = try? CBOR.decode(cborData),
               case .map(let map) = cbor {
                // Extract values from CBOR map
                for (key, value) in map {
                    if case .utf8String(let keyStr) = key {
                        if case .utf8String(let valueStr) = value {
                            if keyStr == "sensitive" {
                                decryptedStruct.sensitive = valueStr
                            } else if keyStr == "password" {
                                decryptedStruct.password = valueStr
                            }
                        }
                    }
                }
            }
        }
        
        // Decrypt fields with label 'system'
        if let encryptedData = self.encrypted_system {
            let decryptedData = try EnvelopeEncryption.decrypt(encryptedData, context: serializationContext)
            let cborData = Array(decryptedData)
            if let cbor = try? CBOR.decode(cborData),
               case .map(let map) = cbor {
                // Extract values from CBOR map
                for (key, value) in map {
                    if case .utf8String(let keyStr) = key {
                        if case .utf8String(let valueStr) = value {
                            if keyStr == "apiKey" {
                                decryptedStruct.apiKey = valueStr
                            }
                        }
                    }
                }
            }
        }
        
        return decryptedStruct
    }
}

final class EncryptionInfrastructureTests: XCTestCase {
    
    func testManualEncryptionDecryption() async throws {
        // Create a test profile
        let originalProfile = ManualTestProfile(
            id: "user123",
            sensitive: "secret data",
            password: "password123",
            apiKey: "api-key-456",
            publicInfo: "public info"
        )
        
        // Create mock serialization context
        let mockKeyManager = MockMobileKeyManager()
        let context = SerializationContext(
            keystore: MockKeyStore(),
            resolver: MockLabelResolver(),
            networkId: "test-network",
            profileId: "test-profile",
            mobileKeyManager: mockKeyManager,
            profileIds: ["test-profile"]
        )
        
        // Test encryption
        let encryptedProfile = try originalProfile.encryptWithContext(context)
        
        // Verify that encrypted profile has the expected structure
        XCTAssertNotNil(encryptedProfile)
        XCTAssertNotNil(encryptedProfile.encrypted_user)
        XCTAssertNotNil(encryptedProfile.encrypted_system)
        
        // Test decryption
        let decryptedProfile = try encryptedProfile.decryptWithContext(context)
        
        // Verify that decrypted profile matches original
        XCTAssertEqual(decryptedProfile.sensitive, originalProfile.sensitive)
        XCTAssertEqual(decryptedProfile.password, originalProfile.password)
        XCTAssertEqual(decryptedProfile.apiKey, originalProfile.apiKey)
    }
    
    func testManualEncryptionWithNilValues() async throws {
        // Create a profile with some nil values
        let originalProfile = ManualTestProfile(
            id: "user123",
            sensitive: nil,
            password: "password123",
            apiKey: nil,
            publicInfo: "public info"
        )
        
        // Create mock serialization context
        let mockKeyManager = MockMobileKeyManager()
        let context = SerializationContext(
            keystore: MockKeyStore(),
            resolver: MockLabelResolver(),
            networkId: "test-network",
            profileId: "test-profile",
            mobileKeyManager: mockKeyManager,
            profileIds: ["test-profile"]
        )
        
        // Test encryption
        let encryptedProfile = try originalProfile.encryptWithContext(context)
        
        // Verify that encrypted profile has the expected structure
        XCTAssertNotNil(encryptedProfile)
        XCTAssertNotNil(encryptedProfile.encrypted_user) // password is set
        XCTAssertNil(encryptedProfile.encrypted_system) // apiKey is nil
        
        // Test decryption
        let decryptedProfile = try encryptedProfile.decryptWithContext(context)
        
        // Verify that decrypted profile matches original (including nil values)
        XCTAssertNil(decryptedProfile.sensitive)
        XCTAssertEqual(decryptedProfile.password, originalProfile.password)
        XCTAssertNil(decryptedProfile.apiKey)
    }
    
    func testManualEncryptionInvalidContext() {
        // Test that encryption fails with invalid context
        let profile = ManualTestProfile(
            id: "user123",
            sensitive: "secret data",
            password: "password123",
            apiKey: "api-key-456",
            publicInfo: "public info"
        )
        
        // Test with nil context
        XCTAssertThrowsError(try profile.encryptWithContext(nil)) { error in
            XCTAssertTrue(error is SerializerError)
        }
        
        // Test with wrong context type
        XCTAssertThrowsError(try profile.encryptWithContext("invalid context")) { error in
            XCTAssertTrue(error is SerializerError)
        }
    }
    
    func testEncryptionFieldGrouping() async throws {
        // Test that fields are properly grouped by encryption labels
        let originalProfile = ManualTestProfile(
            id: "user123",
            sensitive: "secret data",
            password: "password123",
            apiKey: "api-key-456",
            publicInfo: "public info"
        )
        
        // Create mock serialization context
        let mockKeyManager = MockMobileKeyManager()
        let context = SerializationContext(
            keystore: MockKeyStore(),
            resolver: MockLabelResolver(),
            networkId: "test-network",
            profileId: "test-profile",
            mobileKeyManager: mockKeyManager,
            profileIds: ["test-profile"]
        )
        
        // Test encryption
        let encryptedProfile = try originalProfile.encryptWithContext(context)
        
        // Verify that fields are grouped correctly
        XCTAssertNotNil(encryptedProfile.encrypted_user) // Contains sensitive and password
        XCTAssertNotNil(encryptedProfile.encrypted_system) // Contains apiKey
        
        // Test decryption
        let decryptedProfile = try encryptedProfile.decryptWithContext(context)
        
        // Verify that all fields are correctly decrypted
        XCTAssertEqual(decryptedProfile.sensitive, originalProfile.sensitive)
        XCTAssertEqual(decryptedProfile.password, originalProfile.password)
        XCTAssertEqual(decryptedProfile.apiKey, originalProfile.apiKey)
    }
    
    static let allTests = [
        ("testManualEncryptionDecryption", testManualEncryptionDecryption),
        ("testManualEncryptionWithNilValues", testManualEncryptionWithNilValues),
        ("testManualEncryptionInvalidContext", testManualEncryptionInvalidContext),
        ("testEncryptionFieldGrouping", testEncryptionFieldGrouping),
    ]
}

// MARK: - CBOR Encoding Helper

/// CBOR encoding helper using SwiftCBOR
private func encodeToCBOR(_ value: Any) throws -> [UInt8] {
    if let dict = value as? [String: Any] {
        // Encode as CBOR map
        var map: [CBOR: CBOR] = [:]
        for (key, val) in dict {
            let keyCBOR = CBOR.utf8String(key)
            let valueCBOR = try encodeToCBORValue(val)
            map[keyCBOR] = valueCBOR
        }
        return CBOR.map(map).encode()
    } else if let array = value as? [Any] {
        // Encode as CBOR array
        let arrayCBOR = try array.map { try encodeToCBORValue($0) }
        return CBOR.array(arrayCBOR).encode()
    } else {
        return try encodeToCBORValue(value).encode()
    }
}

/// Helper to convert Any to CBOR value
private func encodeToCBORValue(_ value: Any) throws -> CBOR {
    if let string = value as? String {
        return CBOR.utf8String(string)
    } else if let int = value as? Int {
        if int >= 0 {
            return CBOR.unsignedInt(UInt64(int))
        } else {
            return CBOR.negativeInt(UInt64(-int - 1))
        }
    } else if let bool = value as? Bool {
        return CBOR.boolean(bool)
    } else if let double = value as? Double {
        return CBOR.double(double)
    } else if value is NSNull {
        return CBOR.null
    } else {
        throw SerializerError.serializationFailed("Unsupported type for CBOR encoding: \(type(of: value))")
    }
}

// MARK: - Mock Implementations

/// Mock key store for testing
private struct MockKeyStore: KeyStore {
    func getKey(for label: String) -> Data? {
        return Data(repeating: 0x42, count: 32) // Mock key
    }
}

/// Mock label resolver for testing
private struct MockLabelResolver: LabelResolver {
    func resolveLabel(_ label: String) -> String? {
        return label // Return label as-is for testing
    }
}

/// Mock mobile key manager for testing
private struct MockMobileKeyManager: MobileKeyManager {
    func encryptWithEnvelope(data: Data, networkId: String?, profileIds: [String]) throws -> EnvelopeEncryptedData {
        // Mock encryption - just return a fake encrypted data structure
        return EnvelopeEncryptedData(
            encryptedData: data, // For testing, just return the original data
            networkId: networkId,
            networkEncryptedKey: Data(repeating: 0x01, count: 32),
            profileEncryptedKeys: Dictionary(uniqueKeysWithValues: profileIds.map { ($0, Data(repeating: 0x02, count: 32)) })
        )
    }
    
    func decryptWithProfile(envelopeData: EnvelopeEncryptedData, profileId: String) throws -> Data {
        // Mock decryption - just return the encrypted data as-is
        return envelopeData.encryptedData
    }
    
    func decryptWithNetwork(envelopeData: EnvelopeEncryptedData) throws -> Data {
        // Mock decryption - just return the encrypted data as-is
        return envelopeData.encryptedData
    }
} 