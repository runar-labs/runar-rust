import SwiftCompilerPlugin
import SwiftSyntax
import SwiftSyntaxBuilder
import SwiftSyntaxMacros

/// Implementation of the `Plain` macro, which generates serialization code for structs.
///
/// This macro automatically implements:
/// - `Codable` conformance for CBOR serialization
/// - Integration with `AnyValue` for zero-copy data handling
/// - Type registration for lazy deserialization
///
/// ## Usage
/// ```swift
/// @Plain
/// struct TestUser {
///     let id: Int
///     let name: String
///     let isActive: Bool
/// }
/// ```
public struct PlainMacro: MemberMacro {
    public static func expansion(
        of node: AttributeSyntax,
        providingMembersOf declaration: some DeclGroupSyntax,
        in context: some MacroExpansionContext
    ) throws -> [DeclSyntax] {
        
        // Ensure we're working with a struct
        guard let structDecl = declaration.as(StructDeclSyntax.self) else {
            throw MacroError("Plain macro can only be applied to structs")
        }
        
        let structName = structDecl.name.text
        
        // Generate the expanded code
        return [
            """
            // MARK: - Plain Macro Generated Code
            
            extension \(raw: structName): Codable {
                // Codable conformance is automatically synthesized by Swift
            }
            
            extension \(raw: structName) {
                /// Convert this struct to an AnyValue for zero-copy serialization
                public func toAnyValue() -> AnyValue {
                    return AnyValue.struct(self)
                }
                
                /// Create this struct from an AnyValue
                public static func fromAnyValue(_ value: AnyValue) throws -> \(raw: structName) {
                    return try value.asType()
                }
            }
            
            // Register this type for lazy deserialization
            extension \(raw: structName) {
                static let _registered = {
                    TypeRegistry.register(\(raw: structName).self) { data in
                        // Decode pure CBOR map to struct
                        let cborData = Array(data)
                        guard let cbor = try? CBOR.decode(cborData) else {
                            throw SerializerError.deserializationFailed("Failed to decode CBOR")
                        }
                        
                        if case .map(let map) = cbor {
                            // Convert CBOR map to struct using reflection
                            let mirror = Mirror(reflecting: \(raw: structName)())
                            var dict: [String: Any] = [:]
                            
                            for (key, value) in map {
                                if case .utf8String(let keyString) = key {
                                    dict[keyString] = try decodeCBORValue(value)
                                }
                            }
                            
                            // Create struct from dictionary
                            return try createStructFromDictionary(dict)
                        } else {
                            throw SerializerError.deserializationFailed("Expected CBOR map for struct")
                        }
                    }
                    return true
                }()
            }
            
            // MARK: - Helper Functions
            
            private func decodeCBORValue(_ cbor: CBOR) throws -> Any {
                switch cbor {
                case .utf8String(let string):
                    return string
                case .unsignedInt(let int):
                    return Int(int)
                case .negativeInt(let int):
                    return -Int(int) - 1
                case .boolean(let bool):
                    return bool
                case .double(let double):
                    return double
                case .null:
                    return NSNull()
                default:
                    throw SerializerError.deserializationFailed("Unsupported CBOR type")
                }
            }
            
            private func createStructFromDictionary(_ dict: [String: Any]) throws -> \(raw: structName) {
                // This is a simplified implementation
                // In a real implementation, you would use reflection to set properties
                // For now, we'll use JSON as an intermediate step
                let jsonData = try JSONSerialization.data(withJSONObject: dict, options: [])
                return try JSONDecoder().decode(\(raw: structName).self, from: jsonData)
            }
            """
        ]
    }
}

/// Error type for macro-related errors
struct MacroError: Error, CustomStringConvertible {
    let message: String
    
    init(_ message: String) {
        self.message = message
    }
    
    var description: String {
        return message
    }
}

/// Plugin for the macro
struct RunarSerializerMacrosPlugin: CompilerPlugin {
    let providingMacros: [Macro.Type] = [
        PlainMacro.self,
    ]
} 