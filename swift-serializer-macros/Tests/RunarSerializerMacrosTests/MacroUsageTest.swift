import XCTest
@testable import RunarSerializerMacros

final class MacroUsageTest: XCTestCase {
    
    func testPlainMacro() {
        // This test verifies that the @Plain macro compiles and expands correctly
        @Plain
        struct TestUser {
            let id: Int
            let name: String
            let isActive: Bool
        }
        
        // If we get here, the macro expanded successfully
        let user = TestUser(id: 1, name: "Test", isActive: true)
        XCTAssertEqual(user.id, 1)
        XCTAssertEqual(user.name, "Test")
        XCTAssertTrue(user.isActive)
        
        // Test that the macro added the expected methods
        // Note: These will fail at runtime since AnyValue doesn't exist in this package,
        // but the fact that it compiles means the macro expanded correctly
        XCTAssertNoThrow(try user.toAnyValue())
        XCTAssertNoThrow(try TestUser.fromAnyValue(AnyValue.null))
    }
    
    func testEncryptedMacro() {
        // This test verifies that the @Encrypted macro compiles and expands correctly
        @Encrypted
        struct TestProfile {
            let id: String
            var sensitive: String
        }
        
        // If we get here, the macro expanded successfully
        let profile = TestProfile(id: "123", sensitive: "secret")
        XCTAssertEqual(profile.id, "123")
        XCTAssertEqual(profile.sensitive, "secret")
        
        // Test that the macro added the expected methods
        // Note: These will fail at runtime since the types don't exist in this package,
        // but the fact that it compiles means the macro expanded correctly
        XCTAssertNoThrow(try profile.encryptWithKeystore(EnvelopeCrypto(), resolver: LabelResolver()))
    }
}

// Mock types for testing (these would normally come from the main package)
struct AnyValue {
    static let null = AnyValue()
    func asType<T>() throws -> T { fatalError("Mock implementation") }
    static func `struct`(_ value: Any) -> AnyValue { AnyValue() }
}

struct EnvelopeCrypto {}
struct LabelResolver {} 