import XCTest
@testable import RunarSerializer
import SwiftCBOR

// Test struct with encryption - similar to Rust TestProfile
@Encrypted
struct TestProfile {
    let id: String
    @EncryptedField(label: "system") var name: String?
    @EncryptedField(label: "user") var privateField: String?
    @EncryptedField(label: "search") var email: String?
    @EncryptedField(label: "system_only") var systemMetadata: String?
}

// Simple struct for basic serialization test
@Plain
struct SimpleStruct {
    let a: Int64
    let b: String
}

// Mock key manager for testing
class MockKeyManager: EnvelopeCrypto {
    func encrypt(_ data: Data, label: String, context: SerializationContext) throws -> Data {
        // Simple mock encryption - just prefix with label
        return "\(label):".data(using: .utf8)! + data
    }
    
    func decrypt(_ data: Data, label: String, context: SerializationContext) throws -> Data {
        // Simple mock decryption - remove label prefix
        let prefix = "\(label):".data(using: .utf8)!
        guard data.starts(with: prefix) else {
            throw SerializerError.encryptionFailed("Invalid encrypted data")
        }
        return data.dropFirst(prefix.count)
    }
}

// Mock label resolver for testing
class MockLabelResolver: LabelResolver {
    private let mappings: [String: LabelKeyInfo]
    
    init(mappings: [String: LabelKeyInfo]) {
        self.mappings = mappings
    }
    
    func resolveLabel(_ label: String) -> LabelKeyInfo? {
        return mappings[label]
    }
}

final class MacroEncryptionTests: XCTestCase {
    
    func testBasicEncryption() throws {
        // Create test profile
        let original = TestProfile(
            id: "123",
            name: "Test User",
            private: "secret123",
            email: "test@example.com",
            systemMetadata: "system_data"
        )
        
        // Create mock key manager and resolver
        let keyManager = MockKeyManager()
        let resolver = MockLabelResolver(mappings: [
            "user": LabelKeyInfo(profileIds: ["profile1"], networkId: nil),
            "system": LabelKeyInfo(profileIds: ["profile1"], networkId: "network1"),
            "system_only": LabelKeyInfo(profileIds: [], networkId: "network1"),
            "search": LabelKeyInfo(profileIds: ["profile1"], networkId: "network1")
        ])
        
        // Test encryption
        let encrypted: EncryptedTestProfile = try original.encryptWithKeystore(keyManager, resolver: resolver)
        
        // Verify encrypted struct has the expected fields
        XCTAssertEqual(encrypted.id, "123")
        XCTAssertNotNil(encrypted.userEncrypted)
        XCTAssertNotNil(encrypted.systemEncrypted)
        XCTAssertNotNil(encrypted.searchEncrypted)
        XCTAssertNotNil(encrypted.systemOnlyEncrypted)
        
        // Test decryption
        let decrypted = try encrypted.decryptWithKeystore(keyManager)
        XCTAssertEqual(decrypted.id, original.id)
        XCTAssertEqual(decrypted.name, original.name)
        XCTAssertEqual(decrypted.private, original.private)
        XCTAssertEqual(decrypted.email, original.email)
        XCTAssertEqual(decrypted.systemMetadata, original.systemMetadata)
    }
    
    func testEncryptionInAnyValue() throws {
        let profile = TestProfile(
            id: "789",
            name: "AnyValue Test",
            private: "arc_secret",
            email: "arc@example.com",
            systemMetadata: "arc_system_data"
        )
        
        // Create AnyValue with struct
        let val = AnyValue.struct(profile)
        XCTAssertEqual(val.category, .struct)
        
        // Create serialization context
        let keyManager = MockKeyManager()
        let resolver = MockLabelResolver(mappings: [
            "user": LabelKeyInfo(profileIds: ["profile1"], networkId: nil),
            "system": LabelKeyInfo(profileIds: ["profile1"], networkId: "network1"),
            "system_only": LabelKeyInfo(profileIds: [], networkId: "network1"),
            "search": LabelKeyInfo(profileIds: ["profile1"], networkId: "network1")
        ])
        
        let context = SerializationContext(
            keystore: keyManager,
            resolver: resolver,
            networkId: "network1",
            profileId: "profile1"
        )
        
        // Serialize with encryption
        let serialized = try val.serialize(context: context)
        
        // Deserialize
        let deserialized = try AnyValue.deserialize(serialized, keystore: keyManager)
        let deserializedProfile: TestProfile = try deserialized.asType()
        
        XCTAssertEqual(deserializedProfile.id, profile.id)
        XCTAssertEqual(deserializedProfile.name, profile.name)
        XCTAssertEqual(deserializedProfile.private, profile.private)
        XCTAssertEqual(deserializedProfile.email, profile.email)
        XCTAssertEqual(deserializedProfile.systemMetadata, profile.systemMetadata)
    }
    
    func testPlainMacroSerialization() throws {
        let simple = SimpleStruct(a: 42, b: "hello")
        
        // Test serialization
        let anyValue = simple.toAnyValue()
        XCTAssertEqual(anyValue.category, .struct)
        
        // Test deserialization
        let serialized = try anyValue.serialize(context: nil)
        let deserialized = try AnyValue.deserialize(serialized, keystore: nil)
        let deserializedSimple: SimpleStruct = try deserialized.asType()
        
        XCTAssertEqual(deserializedSimple.a, simple.a)
        XCTAssertEqual(deserializedSimple.b, simple.b)
    }
    
    func testMixedEncryptionAndPlain() throws {
        // Test that we can mix encrypted and plain fields
        let profile = TestProfile(
            id: "mixed", // This is plain (no @EncryptedField)
            name: "Mixed Test", // This is encrypted
            private: "mixed_secret", // This is encrypted
            email: "mixed@example.com", // This is encrypted
            systemMetadata: "mixed_system" // This is encrypted
        )
        
        let keyManager = MockKeyManager()
        let resolver = MockLabelResolver(mappings: [
            "user": LabelKeyInfo(profileIds: ["profile1"], networkId: nil),
            "system": LabelKeyInfo(profileIds: ["profile1"], networkId: "network1"),
            "system_only": LabelKeyInfo(profileIds: [], networkId: "network1"),
            "search": LabelKeyInfo(profileIds: ["profile1"], networkId: "network1")
        ])
        
        // Test that plain fields are not encrypted
        let encrypted: EncryptedTestProfile = try profile.encryptWithKeystore(keyManager, resolver: resolver)
        XCTAssertEqual(encrypted.id, "mixed") // Should be plain text
        
        // Test that encrypted fields are encrypted
        XCTAssertNotNil(encrypted.userEncrypted)
        XCTAssertNotNil(encrypted.systemEncrypted)
        XCTAssertNotNil(encrypted.searchEncrypted)
        XCTAssertNotNil(encrypted.systemOnlyEncrypted)
    }
    
    func testLabelBasedAccessControl() throws {
        // This test simulates different access levels based on labels
        let profile = TestProfile(
            id: "access_test",
            name: "Access Test",
            private: "user_only_secret",
            email: "shared@example.com",
            systemMetadata: "system_only_data"
        )
        
        let keyManager = MockKeyManager()
        
        // Create resolver that only gives access to user fields
        let userOnlyResolver = MockLabelResolver(mappings: [
            "user": LabelKeyInfo(profileIds: ["profile1"], networkId: nil),
            "system": LabelKeyInfo(profileIds: ["profile1"], networkId: nil),
            "search": LabelKeyInfo(profileIds: ["profile1"], networkId: nil),
            // Note: system_only not included - no access
        ])
        
        let encrypted: EncryptedTestProfile = try profile.encryptWithKeystore(keyManager, resolver: userOnlyResolver)
        
        // Test decryption with limited access
        let decrypted = try encrypted.decryptWithKeystore(keyManager)
        XCTAssertEqual(decrypted.id, profile.id)
        XCTAssertEqual(decrypted.name, profile.name)
        XCTAssertEqual(decrypted.private, profile.private)
        XCTAssertEqual(decrypted.email, profile.email)
        // systemMetadata should be empty or default since no access
        XCTAssertTrue(decrypted.systemMetadata.isEmpty)
    }
} 