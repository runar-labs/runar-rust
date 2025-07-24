import SwiftCompilerPlugin
import SwiftSyntax
import SwiftSyntaxBuilder
import SwiftSyntaxMacros
import SwiftCBOR

/// Implementation of the `Encrypted` macro, which generates encryption code for structs.
///
/// This macro automatically adds:
/// - Type alias for the encrypted version
/// - Encrypted struct definition with encryption/decryption methods
/// - Real encryption/decryption implementation
/// - Type registration in the global TypeRegistry
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
            public func encryptWithKeystore(_ keystore: EnvelopeCrypto, resolver: LabelResolver) async throws -> \(raw: encryptedStructName) {
                // Ensure the type is registered for deserialization
                await Self.ensureRegistered()
                
                // Serialize the struct to CBOR for encrypted types
                let anyValue = AnyValue.struct(self)
                let serialized = try anyValue.serialize(context: nil)
                
                // Use real envelope encryption from swift-keys
                let labelInfo = resolver.resolveLabel("\(raw: structName.lowercased())")
                let envelopeData = try keystore.encryptWithEnvelope(
                    data: serialized,
                    networkId: labelInfo?.networkId,
                    profileIds: labelInfo?.profileIds ?? []
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
                    // Use real envelope decryption from swift-keys
                    let decryptedData: Data
                    
                    // Try network-based decryption first (most reliable)
                    if encryptedData.networkId != nil && !encryptedData.networkEncryptedKey.isEmpty {
                        decryptedData = try keystore.decryptWithNetwork(envelopeData: encryptedData)
                    } else if let firstProfileId = encryptedData.profileEncryptedKeys.keys.first {
                        // Fall back to profile-based decryption
                        decryptedData = try keystore.decryptWithProfile(envelopeData: encryptedData, profileId: firstProfileId)
                    } else {
                        throw SerializerError.deserializationFailed("No valid decryption method available")
                    }
                    
                    // Deserialize CBOR data back to AnyValue and convert to struct
                    let anyValue = try AnyValue.deserialize(decryptedData, keystore: nil)
                    return try await anyValue.asType() as \(raw: structName)
                }
            }
            
            /// Register this type in the global TypeRegistry for deserialization
            private static func ensureRegistered() async {
                await TypeRegistry.shared.register(\(raw: structName).self) { data in
                    // Use CodableCBORDecoder to decode CBOR data back to the struct
                    let decoder = CodableCBORDecoder()
                    return try decoder.decode(\(raw: structName).self, from: data)
                }
            }
            """
        ]
    }
}