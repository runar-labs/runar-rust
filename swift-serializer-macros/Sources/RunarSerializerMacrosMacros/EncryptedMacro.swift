import SwiftCompilerPlugin
import SwiftSyntax
import SwiftSyntaxBuilder
import SwiftSyntaxMacros

/// Implementation of the `Encrypted` macro, which generates encryption code for structs.
///
/// This macro automatically adds:
/// - `RunarEncryptable` protocol conformance methods
/// - Type alias for the encrypted version
///
/// ## Usage
/// ```swift
/// @Encrypted
/// struct TestProfile {
///     let id: String
///     @EncryptedField(label: "user") var sensitive: String
/// }
/// ```
public struct EncryptedMacro: MemberMacro {
    public static func expansion(
        of node: AttributeSyntax,
        providingMembersOf declaration: some DeclGroupSyntax,
        in context: some MacroExpansionContext
    ) throws -> [DeclSyntax] {
        
        // Only support structs
        guard let structDecl = declaration.as(StructDeclSyntax.self) else {
            throw MacroError("Encrypted macro only supports structs")
        }
        
        return [
            """
            /// Type alias for the encrypted version of this struct
            public typealias Encrypted = Data
            
            /// Encrypt this struct using the provided keystore
            public func encryptWithKeystore(_ keystore: EnvelopeCrypto, resolver: LabelResolver) throws -> Data {
                // Implementation will be provided by the main package
                fatalError("Encryption implementation not yet available")
            }
            """
        ]
    }
} 