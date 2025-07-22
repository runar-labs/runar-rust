import Foundation
import SwiftCBOR

/// Plain macro for automatic struct serialization
/// Usage: @Plain struct MyStruct { ... }
@attached(member)
public macro Plain() = #externalMacro(module: "RunarSerializerMacros", type: "PlainMacro")



/// Error types for serialization operations
public enum SerializerError: Error {
    case deserializationFailed(String)
    case encryptionFailed(String)
    case typeMismatch(String)
    case invalidCategory(UInt8)
    case emptyData
    case typeNameTooLong(String)
    case serializationFailed(String)
}

/// Categories for different value types, matching Rust implementation
public enum ValueCategory: UInt8, CaseIterable {
    case null = 0
    case primitive = 1
    case list = 2
    case map = 3
    case `struct` = 4
    case bytes = 5
    case json = 6
    
    /// Create category from raw value
    public static func from(_ value: UInt8) -> ValueCategory? {
        return ValueCategory(rawValue: value)
    }
}

/// Protocol for type-erased values
public protocol AnyValueProtocol: AnyObject {
    var typeName: String { get }
    var category: ValueCategory { get }
    func serialize(context: SerializationContext?) throws -> Data
    func asType<T>() -> T?
}

/// Type-erased box for storing values
private class AnyValueBox {
    let typeName: String
    let category: ValueCategory
    private let serializeFn: (SerializationContext?) throws -> Data
    private let asTypeFn: (Any.Type) -> Any?
    
    init<T>(
        value: T,
        typeName: String,
        category: ValueCategory,
        serializeFn: @escaping (SerializationContext?) throws -> Data,
        asTypeFn: @escaping (Any.Type) -> Any?
    ) {
        self.typeName = typeName
        self.category = category
        self.serializeFn = serializeFn
        self.asTypeFn = asTypeFn
    }
    
    func serialize(context: SerializationContext?) throws -> Data {
        return try serializeFn(context)
    }
    
    func asType<T>() -> T? {
        return asTypeFn(T.self) as? T
    }
}

/// Main container type for zero-copy data handling
public class AnyValue {
    private let box: AnyValueBox
    public let category: ValueCategory
    
    // Lazy deserialization support
    private var materializedValue: Any?
    private var lazyData: LazyData?
    
    /// Create a null value
    public static func null() -> AnyValue {
        return AnyValue(category: .null, typeName: "null")
    }
    
    /// Check if this is a null value
    public var isNull: Bool {
        return category == .null
    }
    
    /// Create a primitive value
    public static func primitive<T: CBOREncodable>(_ value: T) -> AnyValue {
        let typeName = String(describing: T.self)
        let serializeFn: (SerializationContext?) throws -> Data = { context in
            // Use SwiftCBOR for binary compatibility with Rust
            return Data(value.encode(options: CBOROptions()))
        }
        
        let asTypeFn: (Any.Type) -> Any? = { targetType in
            if targetType == T.self {
                return value
            }
            return nil
        }
        
        let box = AnyValueBox(
            value: value,
            typeName: typeName,
            category: .primitive,
            serializeFn: serializeFn,
            asTypeFn: asTypeFn
        )
        
        return AnyValue(box: box, category: .primitive)
    }
    
    /// Create a bytes value
    public static func bytes(_ data: Data) -> AnyValue {
        let typeName = "Data"
        let serializeFn: (SerializationContext?) throws -> Data = { _ in
            return data
        }
        
        let asTypeFn: (Any.Type) -> Any? = { targetType in
            if targetType == Data.self {
                return data
            }
            return nil
        }
        
        let box = AnyValueBox(
            value: data as AnyObject,
            typeName: typeName,
            category: .bytes,
            serializeFn: serializeFn,
            asTypeFn: asTypeFn
        )
        
        return AnyValue(box: box, category: .bytes)
    }
    
    /// Create a struct value
    public static func `struct`<T: Codable>(_ value: T) -> AnyValue {
        let typeName = String(describing: T.self)
        let serializeFn: (SerializationContext?) throws -> Data = { context in
            // Use pure CBOR encoding for structs
            // Convert struct to dictionary and encode as CBOR map
            let mirror = Mirror(reflecting: value)
            var dict: [String: Any] = [:]
            
            for child in mirror.children {
                if let label = child.label {
                    dict[label] = child.value
                }
            }
            
            return Data(try encodeToCBOR(dict))
        }
        
        let asTypeFn: (Any.Type) -> Any? = { targetType in
            if targetType == T.self {
                return value
            }
            return nil
        }
        
        let box = AnyValueBox(
            value: value,
            typeName: typeName,
            category: .struct,
            serializeFn: serializeFn,
            asTypeFn: asTypeFn
        )
        
        return AnyValue(box: box, category: .struct)
    }
    
    /// Create a lazy value for deferred deserialization
    public static func lazy(category: ValueCategory, lazyData: LazyData) -> AnyValue {
        let box = AnyValueBox(
            value: lazyData,
            typeName: lazyData.typeName,
            category: category,
            serializeFn: { context in
                // Return the original serialized data
                return lazyData.data
            },
            asTypeFn: { _ in nil } // Will be handled by lazy deserialization
        )
        
        return AnyValue(box: box, category: category, lazyData: lazyData)
    }
    
    /// Private initializer
    private init(box: AnyValueBox, category: ValueCategory, lazyData: LazyData? = nil) {
        self.box = box
        self.category = category
        self.lazyData = lazyData
    }
    
    /// Private initializer for null values
    private init(category: ValueCategory, typeName: String) {
        let serializeFn: (SerializationContext?) throws -> Data = { _ in
            return Data()
        }
        
        let asTypeFn: (Any.Type) -> Any? = { _ in
            return nil
        }
        
        let box = AnyValueBox(
            value: NSObject(),
            typeName: typeName,
            category: category,
            serializeFn: serializeFn,
            asTypeFn: asTypeFn
        )
        
        self.box = box
        self.category = category
    }
    
    /// Get the type name of the contained value
    public var typeName: String {
        return box.typeName
    }
    
    /// Serialize the value
    public func serialize(context: SerializationContext? = nil) throws -> Data {
        if isNull {
            return Data([0]) // Single byte for null
        }
        
        let typeName = box.typeName
        let categoryByte = category.rawValue
        
        var buf = Data()
        buf.append(categoryByte)
        
        let typeNameBytes = typeName.data(using: .utf8)!
        if typeNameBytes.count > 255 {
            throw SerializerError.typeNameTooLong(typeName)
        }
        
        if let ctx = context {
            // Encrypted serialization
            let bytes = try box.serialize(context: context)
            // TODO: Implement encryption with keystore
            let isEncryptedByte: UInt8 = 0x01
            buf.append(isEncryptedByte)
            buf.append(UInt8(typeNameBytes.count))
            buf.append(typeNameBytes)
            buf.append(bytes)
        } else {
            // Plain serialization
            let bytes = try box.serialize(context: nil)
            let isEncryptedByte: UInt8 = 0x00
            buf.append(isEncryptedByte)
            buf.append(UInt8(typeNameBytes.count))
            buf.append(typeNameBytes)
            buf.append(bytes)
        }
        
        return buf
    }
    
    /// Get the value as a specific type
    public func asType<T>() async throws -> T {
        // First, try to get from materialized value
        if let value = materializedValue {
            guard let result = value as? T else {
                throw SerializerError.typeMismatch("Cannot cast \(typeName) to \(T.self)")
            }
            return result
        }
        
        // Try to get from box (for already loaded values)
        if let result = box.asType() as T? {
            return result
        }
        
        // Try lazy deserialization
        if let lazyData = lazyData {
            let value = try await deserializeLazyData(lazyData)
            materializedValue = value
            
            guard let result = value as? T else {
                throw SerializerError.typeMismatch("Cannot cast deserialized value to \(T.self)")
            }
            return result
        }
        
        throw SerializerError.typeMismatch("Cannot get value as \(T.self)")
    }
    
    /// Deserialize lazy data into a concrete value
    private func deserializeLazyData(_ lazyData: LazyData) async throws -> Any {
        // TODO: Implement decryption if needed
        if lazyData.encrypted {
            throw SerializerError.deserializationFailed("Encrypted deserialization not yet implemented")
        }
        
        // For now, handle basic primitive types
        switch lazyData.typeName {
        case "String":
            // Try to decode as CBOR string
            let cborData = Array(lazyData.data)
            if let cbor = try? CBOR.decode(cborData) {
                switch cbor {
                case .utf8String(let string):
                    return string
                default:
                    throw SerializerError.deserializationFailed("Invalid CBOR format for String")
                }
            }
            throw SerializerError.deserializationFailed("Failed to decode String from CBOR")
            
        case "Int":
            // Try to decode as CBOR integer
            let cborData = Array(lazyData.data)
            if let cbor = try? CBOR.decode(cborData) {
                switch cbor {
                case .unsignedInt(let int):
                    return Int(int)
                case .negativeInt(let int):
                    return -Int(int) - 1
                default:
                    throw SerializerError.deserializationFailed("Invalid CBOR format for Int")
                }
            }
            throw SerializerError.deserializationFailed("Failed to decode Int from CBOR")
            
        case "Bool":
            // Try to decode as CBOR boolean
            let cborData = Array(lazyData.data)
            if let cbor = try? CBOR.decode(cborData) {
                switch cbor {
                case .boolean(let bool):
                    return bool
                default:
                    throw SerializerError.deserializationFailed("Invalid CBOR format for Bool")
                }
            }
            throw SerializerError.deserializationFailed("Failed to decode Bool from CBOR")
            
        default:
            // Try to find a registered decoder for this type
            if let decoder = await TypeRegistry.shared.getDecoder(for: lazyData.typeName) {
                return try decoder(lazyData.data)
            }
            
            throw SerializerError.deserializationFailed("Unsupported type for lazy deserialization: \(lazyData.typeName)")
        }
    }
    
    /// Deserialize from data
    public static func deserialize(_ data: Data, keystore: KeyStore? = nil) throws -> AnyValue {
        guard !data.isEmpty else {
            throw SerializerError.emptyData
        }
        
        let categoryByte = data[0]
        guard let category = ValueCategory.from(categoryByte) else {
            throw SerializerError.invalidCategory(categoryByte)
        }
        
        if category == .null {
            return AnyValue.null()
        }
        
        // Parse the binary format: [category][encrypted][type_name_len][type_name][data]
        guard data.count >= 3 else {
            throw SerializerError.deserializationFailed("Data too short for non-null value")
        }
        
        let isEncryptedByte = data[1]
        let typeNameLen = Int(data[2])
        
        guard data.count >= 3 + typeNameLen else {
            throw SerializerError.deserializationFailed("Data too short for type name")
        }
        
        let typeNameData = data[3..<(3 + typeNameLen)]
        guard let typeName = String(data: Data(typeNameData), encoding: .utf8) else {
            throw SerializerError.deserializationFailed("Invalid type name encoding")
        }
        
        let dataStart = 3 + typeNameLen
        let valueData = data[dataStart...]
        let isEncrypted = isEncryptedByte == 0x01
        
        // Create lazy data for deferred deserialization
        let lazyData = LazyData(
            typeName: typeName,
            data: Data(valueData),
            keystore: keystore,
            encrypted: isEncrypted
        )
        
        // For now, handle basic cases that can be immediately deserialized
        switch category {
        case .bytes:
            // For bytes, the data is already in the correct format
            return AnyValue.bytes(Data(valueData))
        default:
            // For other categories, create lazy deserialization
            return AnyValue.lazy(category: category, lazyData: lazyData)
        }
    }
}

/// CBOR encoding helper using SwiftCBOR
private func encodeToCBOR(_ value: Any) throws -> [UInt8] {
    switch value {
    case let dict as [String: Any]:
        // Encode as CBOR map
        var map: [CBOR: CBOR] = [:]
        for (key, val) in dict {
            let keyCBOR = CBOR.utf8String(key)
            let valueCBOR = try encodeToCBORValue(val)
            map[keyCBOR] = valueCBOR
        }
        return CBOR.map(map).encode()
        
    case let array as [Any]:
        // Encode as CBOR array
        let arrayCBOR = try array.map { try encodeToCBORValue($0) }
        return CBOR.array(arrayCBOR).encode()
        
    default:
        return try encodeToCBORValue(value).encode()
    }
}

/// Helper to convert Any to CBOR value
private func encodeToCBORValue(_ value: Any) throws -> CBOR {
    switch value {
    case let string as String:
        return CBOR.utf8String(string)
        
    case let int as Int:
        if int >= 0 {
            return CBOR.unsignedInt(UInt64(int))
        } else {
            return CBOR.negativeInt(UInt64(-int - 1))
        }
        
    case let bool as Bool:
        return CBOR.boolean(bool)
        
    case let double as Double:
        return CBOR.double(double)
        
    case is NSNull:
        return CBOR.null
        
    default:
        throw SerializerError.serializationFailed("Unsupported type for CBOR encoding: \(type(of: value))")
    }
}

/// Lazy data structure for deferred deserialization
public struct LazyData {
    let typeName: String
    let data: Data
    let keystore: KeyStore?
    let encrypted: Bool
}

/// Protocol for types that can be automatically serialized
public protocol PlainSerializable: Codable {
    /// Convert this type to an AnyValue
    func toAnyValue() -> AnyValue
    
    /// Create this type from an AnyValue
    static func fromAnyValue(_ value: AnyValue) async throws -> Self
}

/// Default implementation for PlainSerializable
public extension PlainSerializable {
    func toAnyValue() -> AnyValue {
        return AnyValue.struct(self)
    }
    
    static func fromAnyValue(_ value: AnyValue) async throws -> Self {
        return try await value.asType()
    }
}

/// Type registry for custom types
public actor TypeRegistry {
    private var decoders: [String: @Sendable (Data) throws -> Any] = [:]
    
    /// Register a decoder for a custom type
    public func register<T: Codable>(_ type: T.Type, decoder: @escaping @Sendable (Data) throws -> T) {
        let typeName = String(describing: type)
        decoders[typeName] = { data in
            return try decoder(data)
        }
    }
    
    /// Get decoder for a type name
    public func getDecoder(for typeName: String) -> (@Sendable (Data) throws -> Any)? {
        return decoders[typeName]
    }
    
    /// Shared instance for global access
    public static let shared = TypeRegistry()
}

/// Placeholder types - these will be implemented later
public protocol KeyStore {
    // TODO: Implement key store interface
}

public protocol LabelResolver {
    // TODO: Implement label resolver interface
}

public struct SerializationContext {
    let keystore: KeyStore
    let resolver: LabelResolver
    let networkId: String
    let profileId: String
    
    public init(keystore: KeyStore, resolver: LabelResolver, networkId: String, profileId: String) {
        self.keystore = keystore
        self.resolver = resolver
        self.networkId = networkId
        self.profileId = profileId
    }
} 