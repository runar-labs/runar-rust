import Foundation
import RunarKeys

/// Protocol for encrypted field types that can be detected during serialization
public protocol EncryptedFieldProtocol {
    /// Get the encryption label for this field
    var encryptionLabel: String { get }
    
    /// Check if the field has a value to encrypt
    var hasValue: Bool { get }
}

/// Property wrapper for selective field encryption
/// Usage: @EncryptedField(label: "user") var sensitiveData: String
@propertyWrapper
public struct EncryptedField<T>: EncryptedFieldProtocol {
    private let label: String
    private var value: T?
    
    public init(label: String) {
        self.label = label
        self.value = nil
    }
    
    public var wrappedValue: T? {
        get { value }
        set { value = newValue }
    }
    
    public var projectedValue: EncryptedField<T> {
        return self
    }
    
    /// Get the encryption label for this field
    public var encryptionLabel: String {
        return label
    }
    
    /// Check if the value is set
    public var hasValue: Bool {
        return value != nil
    }
}

/// Protocol for types that can be encrypted
public protocol Encryptable {
    /// Convert to data for encryption
    func toData() throws -> Data
    
    /// Create from decrypted data
    static func fromData(_ data: Data) throws -> Self
}

// MARK: - Default Encryptable Implementations

extension String: Encryptable {
    public func toData() throws -> Data {
        guard let data = self.data(using: .utf8) else {
            throw SerializerError.encryptionFailed("Failed to encode string to UTF-8")
        }
        return data
    }
    
    public static func fromData(_ data: Data) throws -> String {
        guard let string = String(data: data, encoding: .utf8) else {
            throw SerializerError.deserializationFailed("Failed to decode string from UTF-8")
        }
        return string
    }
}

extension Data: Encryptable {
    public func toData() throws -> Data {
        return self
    }
    
    public static func fromData(_ data: Data) throws -> Data {
        return data
    }
}

extension Int: Encryptable {
    public func toData() throws -> Data {
        return Swift.withUnsafeBytes(of: self.bigEndian) { Data($0) }
    }
    
    public static func fromData(_ data: Data) throws -> Int {
        guard data.count == MemoryLayout<Int>.size else {
            throw SerializerError.deserializationFailed("Invalid data size for Int")
        }
        return data.withUnsafeBytes { $0.load(as: Int.self).bigEndian }
    }
}

extension Bool: Encryptable {
    public func toData() throws -> Data {
        return Data([self ? 1 : 0])
    }
    
    public static func fromData(_ data: Data) throws -> Bool {
        guard data.count == 1 else {
            throw SerializerError.deserializationFailed("Invalid data size for Bool")
        }
        return data[0] != 0
    }
}

extension Double: Encryptable {
    public func toData() throws -> Data {
        return withUnsafeBytes(of: self.bitPattern.bigEndian) { Data($0) }
    }
    
    public static func fromData(_ data: Data) throws -> Double {
        guard data.count == MemoryLayout<Double>.size else {
            throw SerializerError.deserializationFailed("Invalid data size for Double")
        }
        let bitPattern = data.withUnsafeBytes { $0.load(as: UInt64.self).bigEndian }
        return Double(bitPattern: bitPattern)
    }
}

// MARK: - Array and Dictionary Extensions

extension Array: Encryptable where Element: Encryptable {
    public func toData() throws -> Data {
        var result = Data()
        
        // Write count as UInt32
        let count = UInt32(self.count)
        result.append(contentsOf: Swift.withUnsafeBytes(of: count.bigEndian) { Data($0) })
        
        // Write each element
        for element in self {
            let elementData = try element.toData()
            let elementLength = UInt32(elementData.count)
            result.append(contentsOf: Swift.withUnsafeBytes(of: elementLength.bigEndian) { Data($0) })
            result.append(elementData)
        }
        
        return result
    }
    
    public static func fromData(_ data: Data) throws -> Array<Element> {
        var result: [Element] = []
        var offset = 0
        
        // Read count
        guard offset + 4 <= data.count else {
            throw SerializerError.deserializationFailed("Incomplete array count")
        }
        let count = UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16 | UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
        offset += 4
        
        // Read each element
        for _ in 0..<count {
            guard offset + 4 <= data.count else {
                throw SerializerError.deserializationFailed("Incomplete array element length")
            }
            let elementLength = UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16 | UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
            offset += 4
            
            guard offset + Int(elementLength) <= data.count else {
                throw SerializerError.deserializationFailed("Incomplete array element data")
            }
            let elementData = data[offset..<(offset + Int(elementLength))]
            let element = try Element.fromData(Data(elementData))
            result.append(element)
            offset += Int(elementLength)
        }
        
        return result
    }
}

extension Dictionary: Encryptable where Key == String, Value: Encryptable {
    public func toData() throws -> Data {
        var result = Data()
        
        // Write count as UInt32
        let count = UInt32(self.count)
        result.append(contentsOf: Swift.withUnsafeBytes(of: count.bigEndian) { Data($0) })
        
        // Write each key-value pair
        for (key, value) in self {
            // Write key
            let keyData = key.data(using: .utf8)!
            let keyLength = UInt32(keyData.count)
            result.append(contentsOf: Swift.withUnsafeBytes(of: keyLength.bigEndian) { Data($0) })
            result.append(keyData)
            
            // Write value
            let valueData = try value.toData()
            let valueLength = UInt32(valueData.count)
            result.append(contentsOf: Swift.withUnsafeBytes(of: valueLength.bigEndian) { Data($0) })
            result.append(valueData)
        }
        
        return result
    }
    
    public static func fromData(_ data: Data) throws -> Dictionary<String, Value> {
        var result: [String: Value] = [:]
        var offset = 0
        
        // Read count
        guard offset + 4 <= data.count else {
            throw SerializerError.deserializationFailed("Incomplete dictionary count")
        }
        let count = UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16 | UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
        offset += 4
        
        // Read each key-value pair
        for _ in 0..<count {
            // Read key
            guard offset + 4 <= data.count else {
                throw SerializerError.deserializationFailed("Incomplete dictionary key length")
            }
            let keyLength = UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16 | UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
            offset += 4
            
            guard offset + Int(keyLength) <= data.count else {
                throw SerializerError.deserializationFailed("Incomplete dictionary key data")
            }
            let keyData = data[offset..<(offset + Int(keyLength))]
            guard let key = String(data: Data(keyData), encoding: .utf8) else {
                throw SerializerError.deserializationFailed("Invalid dictionary key encoding")
            }
            offset += Int(keyLength)
            
            // Read value
            guard offset + 4 <= data.count else {
                throw SerializerError.deserializationFailed("Incomplete dictionary value length")
            }
            let valueLength = UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16 | UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
            offset += 4
            
            guard offset + Int(valueLength) <= data.count else {
                throw SerializerError.deserializationFailed("Incomplete dictionary value data")
            }
            let valueData = data[offset..<(offset + Int(valueLength))]
            let value = try Value.fromData(Data(valueData))
            result[key] = value
            offset += Int(valueLength)
        }
        
        return result
    }
}

// MARK: - Encryption Utilities

/// Utilities for working with encrypted property wrappers
public struct EncryptedFieldUtils {
    
    /// Encrypt a field value using envelope encryption (generic version)
    /// - Parameters:
    ///   - field: The encrypted field wrapper
    ///   - context: Serialization context with key manager
    /// - Returns: Envelope encrypted data if the field has a value, nil otherwise
    public static func encryptField<T: Encryptable>(
        _ field: EncryptedField<T>,
        context: SerializationContext
    ) throws -> EnvelopeEncryptedData? {
        guard let value = field.wrappedValue else {
            return nil // No value to encrypt
        }
        
        // Convert value to data
        let data = try value.toData()
        
        // Create encryption context with resolved profile
        let encryptionContext = SerializationContext(
            keystore: context.keystore,
            resolver: context.resolver,
            networkId: context.networkId,
            profileId: context.profileId
        )
        
        // Encrypt using envelope encryption
        return try EnvelopeEncryption.encrypt(data, context: encryptionContext)
    }
    

    
    /// Decrypt a field value from envelope encrypted data
    /// - Parameters:
    ///   - envelopeData: The envelope encrypted data
    ///   - context: Serialization context with key manager
    ///   - type: The type to decrypt to
    /// - Returns: Decrypted value
    public static func decryptField<T: Encryptable>(
        _ envelopeData: EnvelopeEncryptedData,
        context: SerializationContext,
        as type: T.Type
    ) throws -> T {
        // Decrypt the data
        let decryptedData = try EnvelopeEncryption.decrypt(envelopeData, context: context)
        
        // Convert data back to the original type
        return try T.fromData(decryptedData)
    }
} 