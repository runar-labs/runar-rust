import XCTest
@testable import RunarSerializer
import RunarSerializerMacros

final class EncryptedMacroTest: XCTestCase {
    
    func testEncryptedMacroBasic() async throws {
        // Test the @Encrypted macro with basic types
        @Encrypted
        struct SecureUser: Codable {
            let id: Int
            let name: String
            let email: String
            let isActive: Bool
        }
        
        // Create an instance
        let user = SecureUser(
            id: 123,
            name: "John Doe",
            email: "john@example.com",
            isActive: true
        )
        
        // Create a mock keystore and resolver
        let keystore = MockEnvelopeCrypto()
        let resolver = MockLabelResolver()
        
        // Test encryption
        let encrypted = try user.encryptWithKeystore(keystore, resolver: resolver)
        XCTAssertNotNil(encrypted.encryptedData)
        XCTAssertFalse(encrypted.encryptedData.encryptedData.isEmpty)
        
        // Test decryption
        let decrypted = try await encrypted.decryptWithKeystore(keystore)
        XCTAssertEqual(decrypted.id, user.id)
        XCTAssertEqual(decrypted.name, user.name)
        XCTAssertEqual(decrypted.email, user.email)
        XCTAssertEqual(decrypted.isActive, user.isActive)
    }
    
    func testEncryptedMacroWithComplexData() async throws {
        // Test with complex data structures
        @Encrypted
        struct SecureProfile: Codable {
            let id: String
            let name: String
            let metadata: [String: String]
            let tags: [String]
            let settings: UserSettings
        }
        
        @Plain
        struct UserSettings: Codable {
            let theme: String
            let notifications: Bool
            let language: String
        }
        
        let profile = SecureProfile(
            id: "user-123",
            name: "Alice Johnson",
            metadata: ["department": "engineering", "role": "developer"],
            tags: ["swift", "ios", "developer"],
            settings: UserSettings(theme: "dark", notifications: true, language: "en")
        )
        
        let keystore = MockEnvelopeCrypto()
        let resolver = MockLabelResolver()
        
        // Test encryption
        let encrypted = try profile.encryptWithKeystore(keystore, resolver: resolver)
        XCTAssertNotNil(encrypted.encryptedData)
        
        // Test decryption
        let decrypted = try await encrypted.decryptWithKeystore(keystore)
        XCTAssertEqual(decrypted.id, profile.id)
        XCTAssertEqual(decrypted.name, profile.name)
        XCTAssertEqual(decrypted.metadata, profile.metadata)
        XCTAssertEqual(decrypted.tags, profile.tags)
        XCTAssertEqual(decrypted.settings.theme, profile.settings.theme)
        XCTAssertEqual(decrypted.settings.notifications, profile.settings.notifications)
        XCTAssertEqual(decrypted.settings.language, profile.settings.language)
    }
    
    func testEncryptedMacroPerformance() async throws {
        // Test performance with larger data
        @Encrypted
        struct SecureData: Codable {
            let id: Int
            let name: String
            let data: [String: String]
            let numbers: [Int]
        }
        
        // Create larger data structure
        var data: [String: String] = [:]
        var numbers: [Int] = []
        
        for i in 0..<100 {
            data["key\(i)"] = "value\(i)"
            numbers.append(i)
        }
        
        let secureData = SecureData(
            id: 1,
            name: "Performance Test",
            data: data,
            numbers: numbers
        )
        
        let keystore = MockEnvelopeCrypto()
        let resolver = MockLabelResolver()
        
        // Test encryption performance
        let encryptionStart = Date()
        let encrypted = try secureData.encryptWithKeystore(keystore, resolver: resolver)
        let encryptionTime = Date().timeIntervalSince(encryptionStart)
        
        XCTAssertLessThan(encryptionTime, 1.0, "Encryption should complete within 1 second")
        
        // Test decryption performance
        let decryptionStart = Date()
        let decrypted = try await encrypted.decryptWithKeystore(keystore)
        let decryptionTime = Date().timeIntervalSince(decryptionStart)
        
        XCTAssertEqual(decrypted.id, secureData.id)
        XCTAssertEqual(decrypted.name, secureData.name)
        XCTAssertEqual(decrypted.data.count, secureData.data.count)
        XCTAssertEqual(decrypted.numbers.count, secureData.numbers.count)
        XCTAssertLessThan(decryptionTime, 1.0, "Decryption should complete within 1 second")
    }
}

// Mock implementations for testing
class MockEnvelopeCrypto: EnvelopeCrypto {
    func encrypt(_ data: Data, label: String, context: SerializationContext) throws -> Data {
        // Simple XOR encryption for testing (not secure, just for demonstration)
        let key = label.data(using: .utf8) ?? Data()
        var encrypted = Data()
        for (index, byte) in data.enumerated() {
            let keyByte = key[index % key.count]
            encrypted.append(byte ^ keyByte)
        }
        return encrypted
    }
    
    func decrypt(_ data: Data, label: String, context: SerializationContext) throws -> Data {
        // XOR decryption is the same as encryption
        return try encrypt(data, label: label, context: context)
    }
}

struct MockLabelResolver: LabelResolver {
    func resolveLabel(_ label: String) -> LabelKeyInfo? {
        // Simple mapping for testing
        let mappings = [
            "secureuser": LabelKeyInfo(profileIds: ["user-profile"], networkId: nil),
            "secureprofile": LabelKeyInfo(profileIds: ["profile-profile"], networkId: "secure-network"),
            "securedata": LabelKeyInfo(profileIds: ["data-profile"], networkId: "data-network")
        ]
        return mappings[label.lowercased()]
    }
} 