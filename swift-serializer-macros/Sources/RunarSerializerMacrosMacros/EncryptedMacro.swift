import SwiftCompilerPlugin
import SwiftSyntax
import SwiftSyntaxBuilder
import SwiftSyntaxMacros

/// Implementation of the `Encrypted` macro, which generates encryption code for structs.
///
/// This macro automatically adds:
/// - Type alias for the encrypted version
/// - Encrypted struct definition with encryption/decryption methods
/// - Real encryption/decryption implementation
///
/// Note: The struct must explicitly conform to `Codable` for this macro to work.
///
/// ## Usage
/// ```swift
/// @Encrypted
/// struct TestProfile: Codable {
///     let id: String
///     var sensitive: String
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
        
        let structName = structDecl.name.text
        let encryptedStructName = "Encrypted\(structName)"
        
        // Check if the struct has Codable conformance
        let hasCodable = structDecl.inheritanceClause?.inheritedTypes.contains { type in
            type.type.as(SimpleTypeIdentifierSyntax.self)?.name.text == "Codable"
        } ?? false
        
        guard hasCodable else {
            throw MacroError("Encrypted macro requires the struct to explicitly conform to Codable")
        }
        
        return [
            """
            /// Type alias for the encrypted version of this struct
            public typealias Encrypted = \(raw: encryptedStructName)
            
            /// Encrypt this struct using the provided keystore
            public func encryptWithKeystore(_ keystore: EnvelopeCrypto, resolver: LabelResolver) throws -> \(raw: encryptedStructName) {
                // Serialize the struct to CBOR
                let anyValue = AnyValue.struct(self)
                let serialized = try anyValue.serialize(context: nil)
                
                // Encrypt the serialized data
                let encryptedData = try keystore.encrypt(serialized, label: "\(raw: structName.lowercased())", context: SerializationContext(
                    keystore: keystore,
                    resolver: resolver,
                    networkId: "default",
                    profileId: "default"
                ))
                
                // Create envelope encrypted data
                let envelopeData = EnvelopeEncryptedData(
                    encryptedData: encryptedData,
                    networkId: "default",
                    networkEncryptedKey: Data(),
                    profileEncryptedKeys: [:]
                )
                
                return \(raw: encryptedStructName)(encryptedData: envelopeData)
            }
            
            /// Encrypted version of \(raw: structName)
            public struct \(raw: encryptedStructName): Codable {
                /// The encrypted data
                public let encryptedData: EnvelopeEncryptedData
                
                public init(encryptedData: EnvelopeEncryptedData) {
                    self.encryptedData = encryptedData
                }
                
                /// Decrypt this struct using the provided keystore
                public func decryptWithKeystore(_ keystore: EnvelopeCrypto) async throws -> \(raw: structName) {
                    // Decrypt the data
                    let decryptedData = try keystore.decrypt(encryptedData.encryptedData, label: "\(raw: structName.lowercased())", context: SerializationContext(
                        keystore: keystore,
                        resolver: DefaultLabelResolver(labelToProfileId: [:]),
                        networkId: "default",
                        profileId: "default"
                    ))
                    
                    // Deserialize back to AnyValue
                    let anyValue = try AnyValue.deserialize(decryptedData, keystore: nil)
                    
                    // Convert back to the original type
                    return try await anyValue.asType()
                }
            }
            """
        ]
    }
}