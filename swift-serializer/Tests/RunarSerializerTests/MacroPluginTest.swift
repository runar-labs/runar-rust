import XCTest
@testable import RunarSerializer

// Test that the macro plugin integration is working
@Plain
struct TestStruct {
    let id: Int
    let name: String
}

final class MacroPluginTest: XCTestCase {
    
    func testPlainMacroWorks() throws {
        // This test will fail if the macro plugin isn't working
        let testStruct = TestStruct(id: 1, name: "test")
        
        // Test that the macro-generated toAnyValue method exists
        let anyValue = testStruct.toAnyValue()
        
        // Test serialization
        let serialized = try anyValue.serialize(context: nil)
        XCTAssertFalse(serialized.isEmpty)
        
        // Test deserialization
        let deserialized = try AnyValue.deserialize(serialized, keystore: nil)
        let deserializedStruct: TestStruct = try deserialized.asType()
        
        XCTAssertEqual(deserializedStruct.id, testStruct.id)
        XCTAssertEqual(deserializedStruct.name, testStruct.name)
    }
} 