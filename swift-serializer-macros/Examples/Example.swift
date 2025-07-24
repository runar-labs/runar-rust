import RunarSerializerMacros

@TestMacro
struct ExampleStruct {
    let value: String
}

func testMacro() {
    let example = ExampleStruct(value: "test")
    example.testFunction()
} 