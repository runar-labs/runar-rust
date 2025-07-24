import XCTest
@testable import RunarSerializerMacros

final class SimpleMacroTest: XCTestCase {
    
    func testTestMacroExpansion() {
        // Test that the macro expands without error
        @TestMacro
        struct SimpleUser {
            let name: String
        }
        
        let user = SimpleUser(name: "Test")
        XCTAssertEqual(user.name, "Test")
        
        // If we get here, the macro expanded successfully
        print("TestMacro expansion test passed")
    }
} 