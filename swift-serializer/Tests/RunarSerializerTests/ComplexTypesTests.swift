import XCTest
@testable import RunarSerializer

final class ComplexTypesTests: XCTestCase {
    
    // MARK: - List Tests
    
    func testListCreation() async {
        let stringValue = AnyValue.primitive("hello")
        let intValue = AnyValue.primitive(42)
        let boolValue = AnyValue.primitive(true)
        
        let list = AnyValue.list([stringValue, intValue, boolValue])
        
        XCTAssertEqual(list.category, .list)
        XCTAssertEqual(list.typeName, "Array<AnyValue>")
        
        // Test type retrieval
        let retrievedList: [AnyValue] = try! await list.asType()
        XCTAssertEqual(retrievedList.count, 3)
        
        let retrievedString: String = try! await retrievedList[0].asType()
        let retrievedInt: Int = try! await retrievedList[1].asType()
        let retrievedBool: Bool = try! await retrievedList[2].asType()
        
        XCTAssertEqual(retrievedString, "hello")
        XCTAssertEqual(retrievedInt, 42)
        XCTAssertEqual(retrievedBool, true)
    }
    
    func testListSerialization() async {
        let stringValue = AnyValue.primitive("test")
        let intValue = AnyValue.primitive(123)
        let list = AnyValue.list([stringValue, intValue])
        
        let serialized = try! list.serialize()
        let deserialized = try! AnyValue.deserialize(serialized)
        
        let retrievedList: [AnyValue] = try! await deserialized.asType()
        XCTAssertEqual(retrievedList.count, 2)
        
        let retrievedString: String = try! await retrievedList[0].asType()
        let retrievedInt: Int = try! await retrievedList[1].asType()
        
        XCTAssertEqual(retrievedString, "test")
        XCTAssertEqual(retrievedInt, 123)
    }
    
    func testEmptyList() async {
        let emptyList = AnyValue.list([])
        XCTAssertEqual(emptyList.category, .list)
        
        let retrievedList: [AnyValue] = try! await emptyList.asType()
        XCTAssertEqual(retrievedList.count, 0)
    }
    
    func testNestedList() async {
        let innerList = AnyValue.list([AnyValue.primitive("nested")])
        let outerList = AnyValue.list([AnyValue.primitive("outer"), innerList])
        
        let retrievedOuterList: [AnyValue] = try! await outerList.asType()
        XCTAssertEqual(retrievedOuterList.count, 2)
        
        let outerString: String = try! await retrievedOuterList[0].asType()
        let nestedList: [AnyValue] = try! await retrievedOuterList[1].asType()
        
        XCTAssertEqual(outerString, "outer")
        XCTAssertEqual(nestedList.count, 1)
        
        let nestedString: String = try! await nestedList[0].asType()
        XCTAssertEqual(nestedString, "nested")
    }
    
    // MARK: - Map Tests
    
    func testMapCreation() async {
        let stringValue = AnyValue.primitive("world")
        let intValue = AnyValue.primitive(99)
        
        let map = AnyValue.map([
            "greeting": stringValue,
            "number": intValue
        ])
        
        XCTAssertEqual(map.category, .map)
        XCTAssertEqual(map.typeName, "Dictionary<String, AnyValue>")
        
        let retrievedMap: [String: AnyValue] = try! await map.asType()
        XCTAssertEqual(retrievedMap.count, 2)
        
        let retrievedString: String = try! await retrievedMap["greeting"]!.asType()
        let retrievedInt: Int = try! await retrievedMap["number"]!.asType()
        
        XCTAssertEqual(retrievedString, "world")
        XCTAssertEqual(retrievedInt, 99)
    }
    
    func testMapSerialization() async {
        let map = AnyValue.map([
            "key1": AnyValue.primitive("value1"),
            "key2": AnyValue.primitive(456)
        ])
        
        let serialized = try! map.serialize()
        let deserialized = try! AnyValue.deserialize(serialized)
        
        let retrievedMap: [String: AnyValue] = try! await deserialized.asType()
        XCTAssertEqual(retrievedMap.count, 2)
        
        let value1: String = try! await retrievedMap["key1"]!.asType()
        let value2: Int = try! await retrievedMap["key2"]!.asType()
        
        XCTAssertEqual(value1, "value1")
        XCTAssertEqual(value2, 456)
    }
    
    func testEmptyMap() async {
        let emptyMap = AnyValue.map([:])
        XCTAssertEqual(emptyMap.category, .map)
        
        let retrievedMap: [String: AnyValue] = try! await emptyMap.asType()
        XCTAssertEqual(retrievedMap.count, 0)
    }
    
    func testNestedMap() async {
        let innerMap = AnyValue.map(["inner": AnyValue.primitive("nested")])
        let outerMap = AnyValue.map([
            "outer": AnyValue.primitive("value"),
            "nested": innerMap
        ])
        
        let retrievedOuterMap: [String: AnyValue] = try! await outerMap.asType()
        XCTAssertEqual(retrievedOuterMap.count, 2)
        
        let outerValue: String = try! await retrievedOuterMap["outer"]!.asType()
        let nestedMap: [String: AnyValue] = try! await retrievedOuterMap["nested"]!.asType()
        
        XCTAssertEqual(outerValue, "value")
        XCTAssertEqual(nestedMap.count, 1)
        
        let nestedValue: String = try! await nestedMap["inner"]!.asType()
        XCTAssertEqual(nestedValue, "nested")
    }
    
    // MARK: - JSON Tests
    
    func testJSONCreation() async {
        let jsonString = """
        {
            "name": "John",
            "age": 30,
            "active": true
        }
        """
        let jsonData = jsonString.data(using: .utf8)!
        let jsonValue = AnyValue.json(jsonData)
        
        XCTAssertEqual(jsonValue.category, .json)
        XCTAssertEqual(jsonValue.typeName, "JSON")
        
        // Test retrieval as Data
        let retrievedData: Data = try! await jsonValue.asType()
        XCTAssertEqual(retrievedData, jsonData)
        
        // Test retrieval as String
        let retrievedString: String = try! await jsonValue.asType()
        XCTAssertEqual(retrievedString, jsonString)
    }
    
    func testJSONSerialization() async {
        let jsonString = """
        {
            "test": "value",
            "number": 123
        }
        """
        let jsonData = jsonString.data(using: .utf8)!
        let jsonValue = AnyValue.json(jsonData)
        
        let serialized = try! jsonValue.serialize()
        let deserialized = try! AnyValue.deserialize(serialized)
        
        let retrievedData: Data = try! await deserialized.asType()
        XCTAssertEqual(retrievedData, jsonData)
        
        let retrievedString: String = try! await deserialized.asType()
        XCTAssertEqual(retrievedString, jsonString)
    }
    
    func testEmptyJSON() async {
        let emptyJSON = AnyValue.json(Data())
        XCTAssertEqual(emptyJSON.category, .json)
        
        let retrievedData: Data = try! await emptyJSON.asType()
        XCTAssertEqual(retrievedData.count, 0)
    }
    
    // MARK: - Mixed Complex Types Tests
    
    func testListWithMap() async {
        let map = AnyValue.map(["key": AnyValue.primitive("value")])
        let list = AnyValue.list([AnyValue.primitive("item"), map])
        
        let retrievedList: [AnyValue] = try! await list.asType()
        XCTAssertEqual(retrievedList.count, 2)
        
        let item: String = try! await retrievedList[0].asType()
        let retrievedMap: [String: AnyValue] = try! await retrievedList[1].asType()
        
        XCTAssertEqual(item, "item")
        XCTAssertEqual(retrievedMap.count, 1)
        
        let value: String = try! await retrievedMap["key"]!.asType()
        XCTAssertEqual(value, "value")
    }
    
    func testMapWithList() async {
        let list = AnyValue.list([AnyValue.primitive("item1"), AnyValue.primitive("item2")])
        let map = AnyValue.map([
            "items": list,
            "count": AnyValue.primitive(2)
        ])
        
        let retrievedMap: [String: AnyValue] = try! await map.asType()
        XCTAssertEqual(retrievedMap.count, 2)
        
        let items: [AnyValue] = try! await retrievedMap["items"]!.asType()
        let count: Int = try! await retrievedMap["count"]!.asType()
        
        XCTAssertEqual(items.count, 2)
        XCTAssertEqual(count, 2)
        
        let item1: String = try! await items[0].asType()
        let item2: String = try! await items[1].asType()
        
        XCTAssertEqual(item1, "item1")
        XCTAssertEqual(item2, "item2")
    }
    
    func testComplexNestedStructure() async {
        // Create a complex nested structure: map containing list containing map containing JSON
        let jsonString = """
        {
            "nested": "data"
        }
        """
        let jsonData = jsonString.data(using: .utf8)!
        let jsonValue = AnyValue.json(jsonData)
        
        let innerMap = AnyValue.map([
            "json": jsonValue,
            "number": AnyValue.primitive(42)
        ])
        
        let list = AnyValue.list([
            AnyValue.primitive("first"),
            innerMap,
            AnyValue.primitive("last")
        ])
        
        let outerMap = AnyValue.map([
            "list": list,
            "description": AnyValue.primitive("complex structure")
        ])
        
        // Test the full structure
        let retrievedOuterMap: [String: AnyValue] = try! await outerMap.asType()
        XCTAssertEqual(retrievedOuterMap.count, 2)
        
        let description: String = try! await retrievedOuterMap["description"]!.asType()
        XCTAssertEqual(description, "complex structure")
        
        let retrievedList: [AnyValue] = try! await retrievedOuterMap["list"]!.asType()
        XCTAssertEqual(retrievedList.count, 3)
        
        let first: String = try! await retrievedList[0].asType()
        let last: String = try! await retrievedList[2].asType()
        XCTAssertEqual(first, "first")
        XCTAssertEqual(last, "last")
        
        let retrievedInnerMap: [String: AnyValue] = try! await retrievedList[1].asType()
        XCTAssertEqual(retrievedInnerMap.count, 2)
        
        let number: Int = try! await retrievedInnerMap["number"]!.asType()
        XCTAssertEqual(number, 42)
        
        let retrievedJSON: String = try! await retrievedInnerMap["json"]!.asType()
        XCTAssertEqual(retrievedJSON, jsonString)
    }
    
    // MARK: - Error Tests
    
    func testTypeMismatch() async {
        let list = AnyValue.list([AnyValue.primitive("test")])
        
        // Try to get as wrong type
        do {
            let _: String = try await list.asType()
            XCTFail("Should have thrown type mismatch error")
        } catch {
            XCTAssertTrue(error is SerializerError)
        }
    }
    
    func testInvalidJSONData() async {
        let invalidData = Data([0xFF, 0xFE, 0xFD]) // Invalid UTF-8
        let jsonValue = AnyValue.json(invalidData)
        
        // Should still work as Data
        let retrievedData: Data = try! await jsonValue.asType()
        XCTAssertEqual(retrievedData, invalidData)
        
        // Should fail as String
        do {
            let _: String = try await jsonValue.asType()
            XCTFail("Should have thrown error for invalid UTF-8")
        } catch {
            // Expected to fail
        }
    }
    
    static let allTests = [
        ("testListCreation", testListCreation),
        ("testListSerialization", testListSerialization),
        ("testEmptyList", testEmptyList),
        ("testNestedList", testNestedList),
        ("testMapCreation", testMapCreation),
        ("testMapSerialization", testMapSerialization),
        ("testEmptyMap", testEmptyMap),
        ("testNestedMap", testNestedMap),
        ("testJSONCreation", testJSONCreation),
        ("testJSONSerialization", testJSONSerialization),
        ("testEmptyJSON", testEmptyJSON),
        ("testListWithMap", testListWithMap),
        ("testMapWithList", testMapWithList),
        ("testComplexNestedStructure", testComplexNestedStructure),
        ("testTypeMismatch", testTypeMismatch),
        ("testInvalidJSONData", testInvalidJSONData)
    ]
} 