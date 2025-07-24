import XCTest
@testable import RunarSerializer

// Simple test struct
@Plain
struct SimpleTestStruct {
    let id: Int
    let name: String
}

final class SimpleMacroTest: XCTestCase {

    func testPlainMacroWorks() throws {
        // This test will fail if the macro plugin isn't working
        let testStruct = SimpleTestStruct(id: 1, name: "test")
        
        // Just test that the struct can be created
        XCTAssertEqual(testStruct.id, 1)
        XCTAssertEqual(testStruct.name, "test")
        
        // Test that the macro-generated toAnyValue method exists
        let anyValue = testStruct.toAnyValue()
        
        // Test that we can serialize it
        let serialized = try anyValue.serialize(context: nil)
        XCTAssertFalse(serialized.isEmpty)
    }
} 