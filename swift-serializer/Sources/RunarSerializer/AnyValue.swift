import Foundation
import SwiftCBOR

/// Error types for serialization operations
public enum SerializerError: Error {
    case deserializationFailed(String)
    case encryptionFailed(String)
    case typeMismatch(String)
    case invalidCategory(UInt8)
    case emptyData
    case typeNameTooLong(String)
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
    private var materializedValue: AnyValueProtocol?
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
    
    /// Private initializer
    private init(box: AnyValueBox, category: ValueCategory) {
        self.box = box
        self.category = category
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
    public func asType<T>() throws -> T {
        if let value = materializedValue {
            // TODO: Implement proper type casting
            guard let result = value as? T else {
                throw SerializerError.typeMismatch("Cannot cast \(typeName) to \(T.self)")
            }
            return result
        }
        
        // Try to get from box
        if let result = box.asType() as T? {
            return result
        }
        
        // TODO: Implement lazy deserialization
        throw SerializerError.typeMismatch("Cannot get value as \(T.self)")
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
        
        // TODO: Implement full deserialization for different categories
        // For now, handle basic cases
        switch category {
        case .primitive:
            // TODO: Implement primitive deserialization
            throw SerializerError.deserializationFailed("Primitive deserialization not yet implemented")
        case .bytes:
            // For bytes, the data is already in the correct format
            return AnyValue.bytes(Data(valueData))
        default:
            throw SerializerError.deserializationFailed("Category \(category) deserialization not yet implemented")
        }
    }
}

/// Lazy data structure for deferred deserialization
public struct LazyData {
    let typeName: String
    let data: Data
    let keystore: KeyStore?
    let encrypted: Bool
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