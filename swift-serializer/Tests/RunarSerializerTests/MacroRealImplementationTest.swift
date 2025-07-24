import XCTest
@testable import RunarSerializer
import RunarSerializerMacros

final class MacroRealImplementationTest: XCTestCase {
    
    func testPlainMacroBasicTypes() async throws {
        // Test the @Plain macro with basic types that are supported by CBOR
        @Plain
        struct SimpleUser: Codable {
            let id: Int
            let name: String
            let isActive: Bool
            let score: Double
        }
        
        // Create an instance
        let user = SimpleUser(
            id: 123,
            name: "John Doe",
            isActive: true,
            score: 95.5
        )
        
        // Test the generated toAnyValue method
        let anyValue = user.toAnyValue()
        XCTAssertEqual(anyValue.typeName, "SimpleUser")
        XCTAssertEqual(anyValue.category, .struct)
        
        // Test serialization
        let serialized = try anyValue.serialize(context: nil)
        XCTAssertFalse(serialized.isEmpty)
        
        // Test deserialization
        let deserialized = try await SimpleUser.fromAnyValue(anyValue)
        XCTAssertEqual(deserialized.id, user.id)
        XCTAssertEqual(deserialized.name, user.name)
        XCTAssertEqual(deserialized.isActive, user.isActive)
        XCTAssertEqual(deserialized.score, user.score)
    }
    
    func testPlainMacroWithArrays() async throws {
        // Test with arrays of various types
        @Plain
        struct UserWithArrays: Codable {
            let id: Int
            let name: String
            let tags: [String]
            let scores: [Double]
            let flags: [Bool]
            let numbers: [Int]
        }
        
        let user = UserWithArrays(
            id: 456,
            name: "Jane Smith",
            tags: ["developer", "swift", "ios"],
            scores: [95.5, 87.2, 92.1],
            flags: [true, false, true],
            numbers: [1, 2, 3, 4, 5]
        )
        
        // Test serialization
        let anyValue = user.toAnyValue()
        let serialized = try anyValue.serialize(context: nil)
        XCTAssertFalse(serialized.isEmpty)
        
        // Test deserialization
        let deserialized = try await UserWithArrays.fromAnyValue(anyValue)
        XCTAssertEqual(deserialized.id, user.id)
        XCTAssertEqual(deserialized.name, user.name)
        XCTAssertEqual(deserialized.tags, user.tags)
        XCTAssertEqual(deserialized.scores, user.scores)
        XCTAssertEqual(deserialized.flags, user.flags)
        XCTAssertEqual(deserialized.numbers, user.numbers)
    }
    
    func testPlainMacroWithDates() async throws {
        // Test with Date types
        @Plain
        struct Event: Codable {
            let id: Int
            let title: String
            let date: Date
            let tags: [String]
        }
        
        let event = Event(
            id: 789,
            title: "Swift Conference",
            date: Date(),
            tags: ["swift", "conference", "2024"]
        )
        
        // Test serialization
        let anyValue = event.toAnyValue()
        let serialized = try anyValue.serialize(context: nil)
        XCTAssertFalse(serialized.isEmpty)
        
        // Test deserialization
        let deserialized = try await Event.fromAnyValue(anyValue)
        XCTAssertEqual(deserialized.id, event.id)
        XCTAssertEqual(deserialized.title, event.title)
        XCTAssertEqual(deserialized.tags, event.tags)
        // Date comparison might have precision issues, so we check it's close
        XCTAssertEqual(deserialized.date.timeIntervalSince1970, event.date.timeIntervalSince1970, accuracy: 1.0)
    }
    
    func testPlainMacroWithDictionaries() async throws {
        // Test with dictionary types
        @Plain
        struct UserProfile: Codable {
            let id: Int
            let name: String
            let metadata: [String: String]
            let scores: [String: Double]
            let flags: [String: Bool]
        }
        
        let profile = UserProfile(
            id: 101,
            name: "Alice Johnson",
            metadata: ["department": "engineering", "role": "developer"],
            scores: ["math": 95.5, "science": 87.2, "english": 92.1],
            flags: ["active": true, "verified": true, "premium": false]
        )
        
        // Test serialization
        let anyValue = profile.toAnyValue()
        let serialized = try anyValue.serialize(context: nil)
        XCTAssertFalse(serialized.isEmpty)
        
        // Test deserialization
        let deserialized = try await UserProfile.fromAnyValue(anyValue)
        XCTAssertEqual(deserialized.id, profile.id)
        XCTAssertEqual(deserialized.name, profile.name)
        XCTAssertEqual(deserialized.metadata, profile.metadata)
        XCTAssertEqual(deserialized.scores, profile.scores)
        XCTAssertEqual(deserialized.flags, profile.flags)
    }
    
    func testPlainMacroComplexNested() async throws {
        // Test with complex nested structures
        @Plain
        struct ComplexData: Codable {
            let id: Int
            let name: String
            let items: [String]
            let scores: [Double]
            let metadata: [String: String]
            let nested: NestedStruct
        }
        
        @Plain
        struct NestedStruct: Codable {
            let value: String
            let count: Int
            let tags: [String]
        }
        
        let complex = ComplexData(
            id: 456,
            name: "Complex Example",
            items: ["item1", "item2", "item3"],
            scores: [95.5, 87.2, 92.1],
            metadata: ["type": "test", "version": "1.0"],
            nested: NestedStruct(value: "nested value", count: 42, tags: ["nested", "test"])
        )
        
        // Test serialization of complex structure
        let anyValue = complex.toAnyValue()
        let serialized = try anyValue.serialize(context: nil)
        XCTAssertFalse(serialized.isEmpty)
        
        // Test deserialization
        let deserialized = try await ComplexData.fromAnyValue(anyValue)
        XCTAssertEqual(deserialized.id, complex.id)
        XCTAssertEqual(deserialized.name, complex.name)
        XCTAssertEqual(deserialized.items, complex.items)
        XCTAssertEqual(deserialized.scores, complex.scores)
        XCTAssertEqual(deserialized.metadata, complex.metadata)
        XCTAssertEqual(deserialized.nested.value, complex.nested.value)
        XCTAssertEqual(deserialized.nested.count, complex.nested.count)
        XCTAssertEqual(deserialized.nested.tags, complex.nested.tags)
    }
    
    func testPlainMacroPerformance() async throws {
        // Test performance with larger data structures
        @Plain
        struct PerformanceTest: Codable {
            let id: Int
            let name: String
            let numbers: [Int]
            let strings: [String]
            let scores: [Double]
            let metadata: [String: String]
        }
        
        // Create a larger data structure
        var numbers: [Int] = []
        var strings: [String] = []
        var scores: [Double] = []
        var metadata: [String: String] = [:]
        
        for i in 0..<1000 {
            numbers.append(i)
            strings.append("string\(i)")
            scores.append(Double(i) * 1.5)
            metadata["key\(i)"] = "value\(i)"
        }
        
        let testData = PerformanceTest(
            id: 1,
            name: "Performance Test",
            numbers: numbers,
            strings: strings,
            scores: scores,
            metadata: metadata
        )
        
        // Test serialization performance
        let start = Date()
        let anyValue = testData.toAnyValue()
        let serialized = try anyValue.serialize(context: nil)
        let serializationTime = Date().timeIntervalSince(start)
        
        XCTAssertFalse(serialized.isEmpty)
        XCTAssertLessThan(serializationTime, 1.0, "Serialization should complete within 1 second")
        
        // Test deserialization performance
        let deserializationStart = Date()
        let deserialized = try await PerformanceTest.fromAnyValue(anyValue)
        let deserializationTime = Date().timeIntervalSince(deserializationStart)
        
        XCTAssertEqual(deserialized.id, testData.id)
        XCTAssertEqual(deserialized.name, testData.name)
        XCTAssertEqual(deserialized.numbers.count, testData.numbers.count)
        XCTAssertEqual(deserialized.strings.count, testData.strings.count)
        XCTAssertEqual(deserialized.scores.count, testData.scores.count)
        XCTAssertEqual(deserialized.metadata.count, testData.metadata.count)
        XCTAssertLessThan(deserializationTime, 1.0, "Deserialization should complete within 1 second")
    }
} 