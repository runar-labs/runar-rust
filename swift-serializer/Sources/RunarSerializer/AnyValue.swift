import Foundation
import SwiftCBOR
// Note: MobileKeyManager import will be added when swift-keys package is added as dependency

// Note: Macro declarations are now in the swift-serializer-macros package
// and imported via the package dependency

// MARK: - Encryption Protocols

/// Protocol for types that can be encrypted
public protocol RunarEncryptable {
    associatedtype Encrypted: RunarDecryptable where Encrypted.Decrypted == Self
    func encryptWithKeystore(_ keystore: EnvelopeCrypto, resolver: LabelResolver) throws -> Encrypted
}

/// Protocol for types that can be decrypted
public protocol RunarDecryptable {
    associatedtype Decrypted: RunarEncryptable where Decrypted.Encrypted == Self
    func decryptWithKeystore(_ keystore: EnvelopeCrypto) throws -> Decrypted
}





/// Error types for serialization operations
public enum SerializerError: Error, LocalizedError {
    case deserializationFailed(String)
    case encryptionFailed(String)
    case typeMismatch(String)
    case invalidCategory(UInt8)
    case emptyData
    case typeNameTooLong(String)
    case serializationFailed(String)
    
    public var errorDescription: String? {
        switch self {
        case .deserializationFailed(let message):
            return "Deserialization failed: \(message)"
        case .encryptionFailed(let message):
            return "Encryption failed: \(message)"
        case .typeMismatch(let message):
            return "Type mismatch: \(message)"
        case .invalidCategory(let category):
            return "Invalid category: \(category)"
        case .emptyData:
            return "Empty data"
        case .typeNameTooLong(let typeName):
            return "Type name too long: \(typeName)"
        case .serializationFailed(let message):
            return "Serialization failed: \(message)"
        }
    }
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
            // Use CBOR encoding for structs by converting to dictionary first
            // This handles nested Codable types properly
            let encoder = JSONEncoder()
            let jsonData = try encoder.encode(value)
            let json = try JSONSerialization.jsonObject(with: jsonData)
            
            // Convert JSON to CBOR
            if let dict = json as? [String: Any] {
                return Data(try encodeToCBOR(dict))
            } else if let array = json as? [Any] {
                return Data(try encodeToCBOR(array))
            } else {
                return Data(try encodeToCBOR(json))
            }
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
    
    /// Create a list value (array of AnyValue)
    public static func list(_ values: [AnyValue]) -> AnyValue {
        let typeName = "Array<AnyValue>"
        let serializeFn: (SerializationContext?) throws -> Data = { context in
            // Serialize each AnyValue in the list
            var serializedData = Data()
            for value in values {
                let valueData = try value.serialize(context: context)
                // Add length prefix for each value
                let length = UInt32(valueData.count)
                let lengthBytes = withUnsafeBytes(of: length.bigEndian) { Data($0) }
                serializedData.append(lengthBytes)
                serializedData.append(valueData)
            }
            return serializedData
        }
        
        let asTypeFn: (Any.Type) -> Any? = { targetType in
            if targetType == [AnyValue].self {
                return values
            }
            return nil
        }
        
        let box = AnyValueBox(
            value: values,
            typeName: typeName,
            category: .list,
            serializeFn: serializeFn,
            asTypeFn: asTypeFn
        )
        
        return AnyValue(box: box, category: .list)
    }
    
    /// Create a map value (dictionary of String to AnyValue)
    public static func map(_ values: [String: AnyValue]) -> AnyValue {
        let typeName = "Dictionary<String, AnyValue>"
        let serializeFn: (SerializationContext?) throws -> Data = { context in
            // Serialize each key-value pair in the map
            var serializedData = Data()
            for (key, value) in values {
                // Serialize key
                let keyData = key.data(using: .utf8)!
                let keyLength = UInt32(keyData.count)
                let keyLengthBytes = withUnsafeBytes(of: keyLength.bigEndian) { Data($0) }
                serializedData.append(keyLengthBytes)
                serializedData.append(keyData)
                
                // Serialize value
                let valueData = try value.serialize(context: context)
                let valueLength = UInt32(valueData.count)
                let valueLengthBytes = withUnsafeBytes(of: valueLength.bigEndian) { Data($0) }
                serializedData.append(valueLengthBytes)
                serializedData.append(valueData)
            }
            return serializedData
        }
        
        let asTypeFn: (Any.Type) -> Any? = { targetType in
            if targetType == [String: AnyValue].self {
                return values
            }
            return nil
        }
        
        let box = AnyValueBox(
            value: values,
            typeName: typeName,
            category: .map,
            serializeFn: serializeFn,
            asTypeFn: asTypeFn
        )
        
        return AnyValue(box: box, category: .map)
    }
    
    /// Create a JSON value (JSON string as Data)
    public static func json(_ jsonData: Data) -> AnyValue {
        let typeName = "JSON"
        let serializeFn: (SerializationContext?) throws -> Data = { _ in
            // Return the JSON data as-is
            return jsonData
        }
        
        let asTypeFn: (Any.Type) -> Any? = { targetType in
            if targetType == Data.self {
                return jsonData
            }
            if targetType == String.self {
                return String(data: jsonData, encoding: .utf8)
            }
            return nil
        }
        
        let box = AnyValueBox(
            value: jsonData,
            typeName: typeName,
            category: .json,
            serializeFn: serializeFn,
            asTypeFn: asTypeFn
        )
        
        return AnyValue(box: box, category: .json)
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
        
        // Handle JSON-encoded structs and basic primitive types
        switch lazyData.typeName {
        case let typeName where typeName.contains("Struct") || typeName.contains("struct"):
            // Try CBOR deserialization for structs
            let cborData = Array(lazyData.data)
            if let cbor = try? CBOR.decode(cborData) {
                switch cbor {
                case .map(let map):
                    // Convert CBOR map back to dictionary
                    var dict: [String: Any] = [:]
                    for (key, value) in map {
                        if case .utf8String(let keyStr) = key {
                            dict[keyStr] = value
                        }
                    }
                    return dict
                default:
                    throw SerializerError.deserializationFailed("Invalid CBOR format for struct")
                }
            }
            throw SerializerError.deserializationFailed("Failed to decode struct from CBOR")
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
            
        case "Array<AnyValue>":
            // Deserialize list of AnyValue
            var values: [AnyValue] = []
            var offset = 0
            let data = lazyData.data
            
            while offset < data.count {
                guard offset + 4 <= data.count else {
                    throw SerializerError.deserializationFailed("Incomplete list data")
                }
                
                // Read length of next value
                guard offset + 4 <= data.count else {
                    throw SerializerError.deserializationFailed("Incomplete list data")
                }
                let length = UInt32(data[offset]) << 24 |
                           UInt32(data[offset + 1]) << 16 |
                           UInt32(data[offset + 2]) << 8 |
                           UInt32(data[offset + 3])
                offset += 4
                
                guard offset + Int(length) <= data.count else {
                    throw SerializerError.deserializationFailed("Incomplete list value data")
                }
                
                // Deserialize the value
                let valueData = data[offset..<(offset + Int(length))]
                let value = try AnyValue.deserialize(Data(valueData), keystore: lazyData.keystore)
                values.append(value)
                offset += Int(length)
            }
            
            return values
            
        case "Dictionary<String, AnyValue>":
            // Deserialize map of String to AnyValue
            var values: [String: AnyValue] = [:]
            var offset = 0
            let data = lazyData.data
            
            while offset < data.count {
                guard offset + 4 <= data.count else {
                    throw SerializerError.deserializationFailed("Incomplete map data")
                }
                
                // Read length of key
                guard offset + 4 <= data.count else {
                    throw SerializerError.deserializationFailed("Incomplete map data")
                }
                let keyLength = UInt32(data[offset]) << 24 |
                              UInt32(data[offset + 1]) << 16 |
                              UInt32(data[offset + 2]) << 8 |
                              UInt32(data[offset + 3])
                offset += 4
                
                guard offset + Int(keyLength) <= data.count else {
                    throw SerializerError.deserializationFailed("Incomplete map key data")
                }
                
                // Read key
                let keyData = data[offset..<(offset + Int(keyLength))]
                guard let key = String(data: Data(keyData), encoding: .utf8) else {
                    throw SerializerError.deserializationFailed("Invalid map key encoding")
                }
                offset += Int(keyLength)
                
                guard offset + 4 <= data.count else {
                    throw SerializerError.deserializationFailed("Incomplete map value length")
                }
                
                // Read length of value
                guard offset + 4 <= data.count else {
                    throw SerializerError.deserializationFailed("Incomplete map value length")
                }
                let valueLength = UInt32(data[offset]) << 24 |
                                UInt32(data[offset + 1]) << 16 |
                                UInt32(data[offset + 2]) << 8 |
                                UInt32(data[offset + 3])
                offset += 4
                
                guard offset + Int(valueLength) <= data.count else {
                    throw SerializerError.deserializationFailed("Incomplete map value data")
                }
                
                // Deserialize the value
                let valueData = data[offset..<(offset + Int(valueLength))]
                let value = try AnyValue.deserialize(Data(valueData), keystore: lazyData.keystore)
                values[key] = value
                offset += Int(valueLength)
            }
            
            return values
            
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
        
        // Handle cases that can be immediately deserialized
        switch category {
        case .bytes:
            // For bytes, the data is already in the correct format
            return AnyValue.bytes(Data(valueData))
        case .json:
            // For JSON, the data is already in the correct format
            return AnyValue.json(Data(valueData))
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

/// Helper to convert Any to CBOR value using full SwiftCBOR capabilities
private func encodeToCBORValue(_ value: Any) throws -> CBOR {
    switch value {
    case let string as String:
        return CBOR.utf8String(string)
        
    case let int as Int:
        return int.toCBOR()
        
    case let int8 as Int8:
        return int8.toCBOR()
        
    case let int16 as Int16:
        return int16.toCBOR()
        
    case let int32 as Int32:
        return int32.toCBOR()
        
    case let int64 as Int64:
        return int64.toCBOR()
        
    case let uint as UInt:
        return uint.toCBOR()
        
    case let uint8 as UInt8:
        return uint8.toCBOR()
        
    case let uint16 as UInt16:
        return uint16.toCBOR()
        
    case let uint32 as UInt32:
        return uint32.toCBOR()
        
    case let uint64 as UInt64:
        return uint64.toCBOR()
        
    case let bool as Bool:
        return CBOR.boolean(bool)
        
    case let float as Float:
        return float.toCBOR()
        
    case let double as Double:
        return double.toCBOR()
        
    case let date as Date:
        return date.toCBOR()
        
    case let data as Data:
        return data.toCBOR()
        
    case let array as [String]:
        return array.toCBOR()
        
    case let array as [Int]:
        return array.toCBOR()
        
    case let array as [Double]:
        return array.toCBOR()
        
    case let array as [Bool]:
        return array.toCBOR()
        
    case let array as [Date]:
        return array.toCBOR()
        
    case let array as [Data]:
        return array.toCBOR()
        
    case let dict as [String: String]:
        return dict.toCBOR()
        
    case let dict as [String: Int]:
        return dict.toCBOR()
        
    case let dict as [String: Double]:
        return dict.toCBOR()
        
    case let dict as [String: Bool]:
        return dict.toCBOR()
        
    case let dict as [String: Date]:
        return dict.toCBOR()
        
    case let dict as [String: Data]:
        return dict.toCBOR()
        
    case let nsDict as NSDictionary:
        // Convert NSDictionary to CBOR map directly
        var map: [CBOR: CBOR] = [:]
        for (key, value) in nsDict {
            if let keyStr = key as? String {
                let keyCBOR = CBOR.utf8String(keyStr)
                let valueCBOR = try encodeToCBORValue(value)
                map[keyCBOR] = valueCBOR
            }
        }
        return CBOR.map(map)
        
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

// MARK: - Encryption Types

/// Protocol for envelope encryption operations
/// Matches the Rust EnvelopeCrypto trait
public protocol EnvelopeCrypto: AnyObject {
    /// Encrypt data with a specific label
    func encrypt(_ data: Data, label: String, context: SerializationContext) throws -> Data
    
    /// Decrypt data with a specific label
    func decrypt(_ data: Data, label: String, context: SerializationContext) throws -> Data
}



/// Placeholder for KeyStore until swift-keys package is added
public protocol KeyStore {
    // TODO: Implement key store interface
}

public struct SerializationContext {
    public let keystore: EnvelopeCrypto
    public let resolver: LabelResolver
    public let networkId: String
    public let profileId: String
    
    public init(keystore: EnvelopeCrypto, resolver: LabelResolver, networkId: String, profileId: String) {
        self.keystore = keystore
        self.resolver = resolver
        self.networkId = networkId
        self.profileId = profileId
    }
} 