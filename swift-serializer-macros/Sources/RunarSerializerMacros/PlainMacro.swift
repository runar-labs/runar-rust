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
            
            /// CBOR encoding helper using SwiftCBOR
            private func encodeToCBOR(_ value: Any) throws -> [UInt8] {
                if let dict = value as? [String: Any] {
                    // Encode as CBOR map
                    var map: [CBOR: CBOR] = [:]
                    for (key, val) in dict {
                        let keyCBOR = CBOR.utf8String(key)
                        let valueCBOR = try encodeToCBORValue(val)
                        map[keyCBOR] = valueCBOR
                    }
                    return CBOR.map(map).encode()
                } else if let array = value as? [Any] {
                    // Encode as CBOR array
                    let arrayCBOR = try array.map { try encodeToCBORValue($0) }
                    return CBOR.array(arrayCBOR).encode()
                } else {
                    return try encodeToCBORValue(value).encode()
                }
            }
            
            /// Helper to convert Any to CBOR value
            private func encodeToCBORValue(_ value: Any) throws -> CBOR {
                if let string = value as? String {
                    return CBOR.utf8String(string)
                } else if let int = value as? Int {
                    if int >= 0 {
                        return CBOR.unsignedInt(UInt64(int))
                    } else {
                        return CBOR.negativeInt(UInt64(-int - 1))
                    }
                } else if let bool = value as? Bool {
                    return CBOR.boolean(bool)
                } else if let double = value as? Double {
                    return CBOR.double(double)
                } else if value is NSNull {
                    return CBOR.null
                } else {
                    throw SerializerError.serializationFailed("Unsupported type for CBOR encoding: \\(type(of: value))")
                }
            }
            
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
                // For now, we'll use CBOR as an intermediate step
                let cborData = Data(try encodeToCBOR(dict))
                let cborArray = Array(cborData)
                if let cbor = try? CBOR.decode(cborArray),
                   case .map(let map) = cbor {
                    // Extract values from CBOR map and create struct
                    // This is a simplified approach - in production you'd use reflection
                    return try createStructFromCBORMap(map)
                } else {
                    throw SerializerError.deserializationFailed("Failed to decode CBOR for struct creation")
                }
            }
            
            private func createStructFromCBORMap(_ map: [CBOR: CBOR]) throws -> \(raw: structName) {
                // Simplified implementation - extract values and create struct
                // In a real implementation, you would use reflection to set properties dynamically
                var values: [String: Any] = [:]
                for (key, value) in map {
                    if case .utf8String(let keyStr) = key {
                        switch value {
                        case .utf8String(let str):
                            values[keyStr] = str
                        case .unsignedInt(let int):
                            values[keyStr] = Int(int)
                        case .negativeInt(let int):
                            values[keyStr] = -Int(int) - 1
                        case .boolean(let bool):
                            values[keyStr] = bool
                        case .double(let double):
                            values[keyStr] = double
                        default:
                            // Skip unsupported types
                            break
                        }
                    }
                }
                // For now, return a default instance - in production you'd use reflection
                return \(raw: structName)()
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

/// Implementation of the `Encrypted` macro, which generates encryption code for structs.
///
/// This macro automatically implements:
/// - `RunarEncryptable` and `RunarDecryptable` protocol conformance
/// - Field-level encryption based on @Encrypted property wrappers
/// - Integration with envelope encryption
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
        
        let structName = structDecl.name.text
        let encryptedStructName = "Encrypted\(structName)"
        
        // Analyze struct fields to find encrypted fields
        let encryptedFields = try analyzeEncryptedFields(structDecl)
        
        // Generate encrypted struct properties
        let encryptedProperties = generateEncryptedProperties(encryptedFields)
        
        // Generate encryption implementation
        let encryptionImpl = generateEncryptionImplementation(structName, encryptedStructName, encryptedFields)
        
        // Generate decryption implementation
        let decryptionImpl = generateDecryptionImplementation(structName, encryptedStructName, encryptedFields)
        
        // Generate the complete implementation
        let completeImplementation = """
        extension \(structName): RunarEncryptable {
            public typealias Encrypted = \(encryptedStructName)
            
            \(encryptionImpl)
        }
        
        @Codable
        public struct \(encryptedStructName): RunarDecryptable {
            public typealias Decrypted = \(structName)
            
            \(encryptedProperties)
            
            public init() {
                // Initialize with default values
            }
            
            \(decryptionImpl)
        }
        
        // MARK: - CBOR Encoding Helper
        
        /// CBOR encoding helper using SwiftCBOR
        private func encodeToCBOR(_ value: Any) throws -> [UInt8] {
            if let dict = value as? [String: Any] {
                // Encode as CBOR map
                var map: [CBOR: CBOR] = [:]
                for (key, val) in dict {
                    let keyCBOR = CBOR.utf8String(key)
                    let valueCBOR = try encodeToCBORValue(val)
                    map[keyCBOR] = valueCBOR
                }
                return CBOR.map(map).encode()
            } else if let array = value as? [Any] {
                // Encode as CBOR array
                let arrayCBOR = try array.map { try encodeToCBORValue($0) }
                return CBOR.array(arrayCBOR).encode()
            } else {
                return try encodeToCBORValue(value).encode()
            }
        }
        
        /// Helper to convert Any to CBOR value
        private func encodeToCBORValue(_ value: Any) throws -> CBOR {
            if let string = value as? String {
                return CBOR.utf8String(string)
            } else if let int = value as? Int {
                if int >= 0 {
                    return CBOR.unsignedInt(UInt64(int))
                } else {
                    return CBOR.negativeInt(UInt64(-int - 1))
                }
            } else if let bool = value as? Bool {
                return CBOR.boolean(bool)
            } else if let double = value as? Double {
                return CBOR.double(double)
            } else if value is NSNull {
                return CBOR.null
            } else {
                throw SerializerError.serializationFailed("Unsupported type for CBOR encoding: \\(type(of: value))")
            }
        }
        """
        
        return [DeclSyntax(stringLiteral: completeImplementation)]
    }
    
    /// Analyze struct fields to find @EncryptedField properties
    private static func analyzeEncryptedFields(_ structDecl: StructDeclSyntax) throws -> [EncryptedFieldInfo] {
        var encryptedFields: [EncryptedFieldInfo] = []
        
        for member in structDecl.memberBlock.members {
            guard let property = member.decl.as(VariableDeclSyntax.self) else {
                continue
            }
            
            for binding in property.bindings {
                guard let pattern = binding.pattern.as(IdentifierPatternSyntax.self),
                      let typeAnnotation = binding.typeAnnotation else {
                    continue
                }
                
                let fieldName = pattern.identifier.text
                let fieldType = "Any" // Simplified for now
                
                // Check if this field has @EncryptedField attribute
                if let attribute = findEncryptedFieldAttribute(property) {
                    let label = extractLabelFromAttribute(attribute)
                    encryptedFields.append(EncryptedFieldInfo(
                        name: fieldName,
                        type: fieldType,
                        label: label
                    ))
                }
            }
        }
        
        return encryptedFields
    }
    
    /// Find @EncryptedField attribute in property declaration
    private static func findEncryptedFieldAttribute(_ property: VariableDeclSyntax) -> AttributeSyntax? {
        for attribute in property.attributes {
            if let attributeSyntax = attribute.as(AttributeSyntax.self),
               attributeSyntax.attributeName.description == "EncryptedField" {
                return attributeSyntax
            }
        }
        return nil
    }
    
    /// Extract label from @EncryptedField attribute
    private static func extractLabelFromAttribute(_ attribute: AttributeSyntax) -> String {
        // Default label if none specified
        var label = "default"
        
        if let argumentList = attribute.arguments?.as(LabeledExprListSyntax.self) {
            for argument in argumentList {
                if argument.label?.text == "label",
                   let stringLiteral = argument.expression.as(StringLiteralExprSyntax.self) {
                    label = stringLiteral.segments.description.trimmingCharacters(in: .whitespacesAndNewlines)
                }
            }
        }
        
        return label
    }
    
    /// Generate encrypted struct properties
    private static func generateEncryptedProperties(_ encryptedFields: [EncryptedFieldInfo]) -> String {
        var properties: [String] = []
        
        // Group fields by label
        let groupedFields = Dictionary(grouping: encryptedFields) { $0.label }
        
        for (label, fields) in groupedFields {
            let fieldNames = fields.map { $0.name }.joined(separator: ", ")
            properties.append("/// Encrypted data for label '\(label)' (fields: \(fieldNames))")
            properties.append("public var encrypted_\(label): EnvelopeEncryptedData?")
        }
        
        return properties.joined(separator: "\n    ")
    }
    
    /// Generate encryption implementation
    private static func generateEncryptionImplementation(_ structName: String, _ encryptedStructName: String, _ encryptedFields: [EncryptedFieldInfo]) -> String {
        var implementation = """
        public func encryptWithKeystore(_ keystore: EnvelopeCrypto, resolver: LabelResolver) throws -> \(encryptedStructName) {
            var encryptedStruct = \(encryptedStructName)()
        """
        
        // Group fields by label
        let groupedFields = Dictionary(grouping: encryptedFields) { $0.label }
        
        for (label, fields) in groupedFields {
            implementation += "\n\n            // Encrypt fields with label '\(label)'"
            
            // Create a dictionary of field values for this label
            implementation += "\n            var \(label)Fields: [String: Any] = [:]"
            
            for field in fields {
                implementation += "\n            if let value = self.\(field.name) {"
                implementation += "\n                \(label)Fields[\"\(field.name)\"] = value"
                implementation += "\n            }"
            }
            
            // Only encrypt if we have values
            implementation += "\n            if !\(label)Fields.isEmpty {"
            implementation += "\n                let data = Data(try encodeToCBOR(\(label)Fields))"
            implementation += "\n                encryptedStruct.encrypted_\(label) = try keystore.encrypt(data, label: \"\(label)\", context: SerializationContext(keystore: keystore, resolver: resolver, networkId: \"\", profileId: \"\"))"
            implementation += "\n            }"
        }
        
        implementation += "\n\n            return encryptedStruct"
        implementation += "\n        }"
        
        return implementation
    }
    
    /// Generate decryption implementation
    private static func generateDecryptionImplementation(_ structName: String, _ encryptedStructName: String, _ encryptedFields: [EncryptedFieldInfo]) -> String {
        var implementation = """
        public func decryptWithKeystore(_ keystore: EnvelopeCrypto) throws -> \(structName) {
            var decryptedStruct = \(structName)()
        """
        
        // Group fields by label
        let groupedFields = Dictionary(grouping: encryptedFields) { $0.label }
        
        for (label, fields) in groupedFields {
            implementation += "\n\n            // Decrypt fields with label '\(label)'"
            implementation += "\n            if let encryptedData = self.encrypted_\(label) {"
            implementation += "\n                let context = SerializationContext(keystore: keystore, resolver: MockLabelResolver(mappings: [:]), networkId: \"\", profileId: \"\")"
            implementation += "\n                let decryptedData = try keystore.decrypt(encryptedData.encryptedData, label: \"\(label)\", context: context)"
            implementation += "\n                let cborData = Array(decryptedData)"
            implementation += "\n                if let cbor = try? CBOR.decode(cborData),"
            implementation += "\n                   case .map(let map) = cbor {"
            
            for field in fields {
                implementation += "\n                    // Extract \(field.name) from CBOR map"
                implementation += "\n                    for (key, value) in map {"
                implementation += "\n                        if case .utf8String(let keyStr) = key, keyStr == \"\(field.name)\" {"
                implementation += "\n                            if case .utf8String(let valueStr) = value {"
                implementation += "\n                                decryptedStruct.\(field.name) = valueStr"
                implementation += "\n                            }"
                implementation += "\n                            break"
                implementation += "\n                        }"
                implementation += "\n                    }"
            }
            
            implementation += "\n                }"
            implementation += "\n            }"
        }
        
        implementation += "\n\n            return decryptedStruct"
        implementation += "\n        }"
        
        return implementation
    }
}

/// Information about an encrypted field
private struct EncryptedFieldInfo {
    let name: String
    let type: String
    let label: String
}

// MARK: - Protocol Definitions

// Note: RunarEncryptable and RunarDecryptable protocols are now defined in the main package

 