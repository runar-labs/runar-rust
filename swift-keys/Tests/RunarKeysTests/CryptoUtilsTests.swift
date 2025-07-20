import XCTest
@testable import RunarKeys

final class CryptoUtilsTests: XCTestCase {
    
    func testCompactIdGeneration() throws {
        // Test with a known public key
        let publicKey = "test-public-key-data".data(using: .utf8)!
        let compactId = CryptoUtils.compactId(publicKey)
        
        XCTAssertFalse(compactId.isEmpty)
        XCTAssertGreaterThan(compactId.count, 0)
        
        // Test that the same input produces the same output
        let sameCompactId = CryptoUtils.compactId(publicKey)
        XCTAssertEqual(compactId, sameCompactId)
        
        // Test that different inputs produce different outputs
        let differentKey = "different-public-key-data".data(using: .utf8)!
        let differentCompactId = CryptoUtils.compactId(differentKey)
        XCTAssertNotEqual(compactId, differentCompactId)
    }
    
    func testRandomIdGeneration() throws {
        let id1 = CryptoUtils.generateRandomId(prefix: "test")
        let id2 = CryptoUtils.generateRandomId(prefix: "test")
        
        XCTAssertTrue(id1.hasPrefix("test-"))
        XCTAssertTrue(id2.hasPrefix("test-"))
        XCTAssertNotEqual(id1, id2) // Should be different each time
        
        let customId = CryptoUtils.generateRandomId(prefix: "custom")
        XCTAssertTrue(customId.hasPrefix("custom-"))
    }
    
    func testP256KeyValidation() throws {
        // Test with valid P-256 keys
        let validKeyPair = try ECDHKeyPair()
        let validPublicKey = validKeyPair.publicKeyBytes()
        let validPrivateKey = validKeyPair.rawScalarBytes()
        
        XCTAssertTrue(CryptoUtils.isValidP256PublicKey(validPublicKey))
        XCTAssertTrue(CryptoUtils.isValidP256PrivateKey(validPrivateKey))
        
        // Test with invalid keys
        let invalidKey = "invalid-key-data".data(using: .utf8)!
        XCTAssertFalse(CryptoUtils.isValidP256PublicKey(invalidKey))
        XCTAssertFalse(CryptoUtils.isValidP256PrivateKey(invalidKey))
        
        // Test with empty data
        XCTAssertFalse(CryptoUtils.isValidP256PublicKey(Data()))
        XCTAssertFalse(CryptoUtils.isValidP256PrivateKey(Data()))
    }
    
    func testKeyConversion() throws {
        let originalKeyPair = try ECDHKeyPair()
        
        // Test conversion to signing key
        let signingKey = try originalKeyPair.toECDSASigningKey()
        XCTAssertEqual(signingKey.rawRepresentation, originalKeyPair.rawScalarBytes())
        
        // Test conversion to verifying key
        let verifyingKey = try originalKeyPair.toECDSAVerifyingKey()
        XCTAssertEqual(verifyingKey.rawRepresentation, originalKeyPair.publicKey.rawRepresentation)
    }
    
    func testBase58Encoding() throws {
        // Test with known data
        let testData = "Hello".data(using: .utf8)!
        let compactId = CryptoUtils.compactId(testData)
        
        // Verify the result contains only base58 characters
        let base58Chars = CharacterSet(charactersIn: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
        let compactIdChars = CharacterSet(charactersIn: compactId)
        
        XCTAssertTrue(compactIdChars.isSubset(of: base58Chars))
    }
    
    func testCompactIdConsistency() throws {
        // Test that compact ID generation is consistent across multiple calls
        let publicKey = "consistent-test-key".data(using: .utf8)!
        
        let id1 = CryptoUtils.compactId(publicKey)
        let id2 = CryptoUtils.compactId(publicKey)
        let id3 = CryptoUtils.compactId(publicKey)
        
        XCTAssertEqual(id1, id2)
        XCTAssertEqual(id2, id3)
        XCTAssertEqual(id1, id3)
    }
    
    func testCompactIdUniqueness() throws {
        // Test that different public keys produce different compact IDs
        let key1 = "key-1".data(using: .utf8)!
        let key2 = "key-2".data(using: .utf8)!
        let key3 = "key-3".data(using: .utf8)!
        
        let id1 = CryptoUtils.compactId(key1)
        let id2 = CryptoUtils.compactId(key2)
        let id3 = CryptoUtils.compactId(key3)
        
        XCTAssertNotEqual(id1, id2)
        XCTAssertNotEqual(id2, id3)
        XCTAssertNotEqual(id1, id3)
    }
} 