import Foundation

/// A simple test macro
@attached(member, names: named(testFunction))
public macro TestMacro() = #externalMacro(module: "RunarSerializerMacrosMacros", type: "TestMacro")

/// Plain macro for automatic struct serialization
/// Usage: @Plain struct MyStruct { ... }
@attached(member, names: named(toAnyValue), named(fromAnyValue))
public macro Plain() = #externalMacro(module: "RunarSerializerMacrosMacros", type: "PlainMacro")

/// Usage: @Encrypted struct MyStruct { @EncryptedField(label: "user") var sensitive: String }
@attached(member, names: named(Encrypted), named(encryptWithKeystore))
public macro Encrypted() = #externalMacro(module: "RunarSerializerMacrosMacros", type: "EncryptedMacro") 