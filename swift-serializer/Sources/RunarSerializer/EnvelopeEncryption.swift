import Foundation
import SwiftCBOR



/// Envelope encrypted data structure from swift-keys package
/// This mirrors the structure from MobileKeyManager for serialization
public struct EnvelopeEncryptedData: Codable {
    /// The encrypted data payload
    public let encryptedData: Data
    /// Network ID this data belongs to
    public let networkId: String?
    /// Envelope key encrypted with network key (always required)
    public let networkEncryptedKey: Data
    /// Envelope key encrypted with each profile key
    public let profileEncryptedKeys: [String: Data]
    
    public init(encryptedData: Data, networkId: String?, networkEncryptedKey: Data, profileEncryptedKeys: [String: Data]) {
        self.encryptedData = encryptedData
        self.networkId = networkId
        self.networkEncryptedKey = networkEncryptedKey
        self.profileEncryptedKeys = profileEncryptedKeys
    }
}

/// Default label resolver that maps labels directly to profile IDs
public struct DefaultLabelResolver: LabelResolver {
    private let labelToProfileId: [String: String]
    
    public init(labelToProfileId: [String: String]) {
        self.labelToProfileId = labelToProfileId
    }
    
    public func resolveLabel(_ label: String) -> LabelKeyInfo? {
        guard let profileId = labelToProfileId[label] else {
            return nil
        }
        return LabelKeyInfo(profileIds: [profileId], networkId: nil)
    }
}

/// Envelope encryption utilities for the serializer
public struct EnvelopeEncryption {
    
    /// Encrypt data using envelope encryption
    /// - Parameters:
    ///   - data: Data to encrypt
    ///   - context: Serialization context with key manager and recipients
    /// - Returns: Envelope encrypted data
    public static func encrypt(
        _ data: Data,
        context: SerializationContext
    ) throws -> EnvelopeEncryptedData {
        // For now, use a simple implementation
        // In production, this would use the actual swift-keys package
        let encryptedData = data // Placeholder - would be actual encryption
        return EnvelopeEncryptedData(
            encryptedData: encryptedData,
            networkId: nil,
            networkEncryptedKey: Data(),
            profileEncryptedKeys: [:]
        )
    }
    
    /// Decrypt data using envelope encryption
    /// - Parameters:
    ///   - envelopeData: Envelope encrypted data
    ///   - context: Serialization context with key manager
    ///   - profileId: Profile ID to decrypt with (if using profile-based decryption)
    /// - Returns: Decrypted data
    public static func decrypt(
        _ envelopeData: EnvelopeEncryptedData,
        context: SerializationContext,
        profileId: String? = nil
    ) throws -> Data {
        // For now, return the data as-is
        // In production, this would use the actual swift-keys package
        return envelopeData.encryptedData
    }
    
    /// Serialize EnvelopeEncryptedData to CBOR format
    /// - Parameter envelopeData: Envelope encrypted data to serialize
    /// - Returns: CBOR encoded data
    public static func serializeToCBOR(_ envelopeData: EnvelopeEncryptedData) throws -> Data {
        // Create a dictionary representation for CBOR encoding
        var dict: [String: Any] = [
            "encryptedData": Array(envelopeData.encryptedData),
            "networkEncryptedKey": Array(envelopeData.networkEncryptedKey),
            "profileEncryptedKeys": envelopeData.profileEncryptedKeys.mapValues { Array($0) }
        ]
        
        if let networkId = envelopeData.networkId {
            dict["networkId"] = networkId
        }
        
        // Encode as CBOR
        return Data(try encodeToCBOR(dict))
    }
    
    /// Deserialize EnvelopeEncryptedData from CBOR format
    /// - Parameter data: CBOR encoded data
    /// - Returns: Envelope encrypted data
    public static func deserializeFromCBOR(_ data: Data) throws -> EnvelopeEncryptedData {
        let cborData = Array(data)
        guard let cbor = try? CBOR.decode(cborData) else {
            throw SerializerError.deserializationFailed("Failed to decode CBOR for envelope data")
        }
        
        guard case .map(let map) = cbor else {
            throw SerializerError.deserializationFailed("Expected CBOR map for envelope data")
        }
        
        // Extract fields from CBOR map
        var encryptedData: Data?
        var networkId: String?
        var networkEncryptedKey: Data?
        var profileEncryptedKeys: [String: Data] = [:]
        
        for (key, value) in map {
            guard case .utf8String(let keyString) = key else { continue }
            
            switch keyString {
            case "encryptedData":
                if case .byteString(let bytes) = value {
                    encryptedData = Data(bytes)
                }
            case "networkId":
                if case .utf8String(let id) = value {
                    networkId = id
                }
            case "networkEncryptedKey":
                if case .byteString(let bytes) = value {
                    networkEncryptedKey = Data(bytes)
                }
            case "profileEncryptedKeys":
                if case .map(let profileMap) = value {
                    for (profileKey, profileValue) in profileMap {
                        if case .utf8String(let profileId) = profileKey,
                           case .byteString(let bytes) = profileValue {
                            profileEncryptedKeys[profileId] = Data(bytes)
                        }
                    }
                }
            default:
                break
            }
        }
        
        guard let encryptedData = encryptedData,
              let networkEncryptedKey = networkEncryptedKey else {
            throw SerializerError.deserializationFailed("Missing required fields in envelope data")
        }
        
        return EnvelopeEncryptedData(
            encryptedData: encryptedData,
            networkId: networkId,
            networkEncryptedKey: networkEncryptedKey,
            profileEncryptedKeys: profileEncryptedKeys
        )
    }
}

// MARK: - CBOR Encoding Helper

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
        
    case let array as [UInt8]:
        return CBOR.byteString(array)
        
    case let dict as [String: [UInt8]]:
        // Handle Dictionary<String, [UInt8]> for profileEncryptedKeys
        var map: [CBOR: CBOR] = [:]
        for (key, val) in dict {
            map[CBOR.utf8String(key)] = CBOR.byteString(val)
        }
        return CBOR.map(map)
        
    case is NSNull:
        return CBOR.null
        
    default:
                    throw SerializerError.encryptionFailed("Unsupported type for CBOR encoding: \(type(of: value))")
    }
} 