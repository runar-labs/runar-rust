import SwiftCompilerPlugin
import SwiftSyntax
import SwiftSyntaxBuilder
import SwiftSyntaxMacros

/// Implementation of the `Plain` macro, which generates serialization code for structs.
///
/// This macro automatically adds:
/// - `toAnyValue()` method for zero-copy serialization
/// - `fromAnyValue()` static method for deserialization
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
        
        return [
            """
            /// Convert this struct to an AnyValue for zero-copy serialization
            public func toAnyValue() -> AnyValue {
                return AnyValue.struct(self)
            }
            
            /// Create this struct from an AnyValue
            public static func fromAnyValue(_ value: AnyValue) throws -> \(raw: structName) {
                return try value.asType()
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

 