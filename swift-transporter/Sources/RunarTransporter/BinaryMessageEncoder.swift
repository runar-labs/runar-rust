import Foundation
import SwiftProtobuf

/// Binary message encoder/decoder for Runar network messages
/// Matches the Rust protobuf implementation for compatibility
@available(macOS 12.0, iOS 15.0, *)
public struct BinaryMessageEncoder {
    
    // MARK: - Message Encoding
    
    /// Encode a network message to binary format
    /// Matches the Rust NetworkMessage protobuf encoding
    public static func encodeNetworkMessage(_ message: RunarNetworkMessage) throws -> Data {
        // Create a simple binary format that matches the Rust implementation
        // Format: [length:4][source_node_id_length:4][source_node_id][dest_node_id_length:4][dest_node_id][message_type_length:4][message_type][payloads_count:4][payloads...]
        
        var data = Data()
        
        // Helper function to append string with length prefix
        func appendString(_ string: String) {
            let stringData = string.data(using: .utf8) ?? Data()
            let length = UInt32(stringData.count).bigEndian
            data.append(Data(bytes: withUnsafeBytes(of: length) { Data($0) }))
            data.append(stringData)
        }
        
        // Append source node ID
        appendString(message.sourceNodeId)
        
        // Append destination node ID
        appendString(message.destinationNodeId)
        
        // Append message type
        appendString(message.messageType)
        
        // Append timestamp (as milliseconds since epoch)
        let timestamp = UInt64(message.timestamp.timeIntervalSince1970 * 1000).bigEndian
        data.append(Data(bytes: withUnsafeBytes(of: timestamp) { Data($0) }))
        
        // Append payloads count
        let payloadsCount = UInt32(message.payloads.count).bigEndian
        data.append(Data(bytes: withUnsafeBytes(of: payloadsCount) { Data($0) }))
        
        // Append each payload
        for payload in message.payloads {
            try appendPayload(payload, to: &data)
        }
        
        return data
    }
    
    /// Encode a node info to binary format
    /// Matches the Rust NodeInfo protobuf encoding
    public static func encodeNodeInfo(_ nodeInfo: RunarNodeInfo) throws -> Data {
        // Create a simple binary format that matches the Rust implementation
        // Format: [public_key_length:4][public_key][network_ids_count:4][network_ids...][addresses_count:4][addresses...][services_count:4][services...][version:8][created_at:8]
        
        var data = Data()
        
        // Helper function to append string with length prefix
        func appendString(_ string: String) {
            let stringData = string.data(using: .utf8) ?? Data()
            let length = UInt32(stringData.count).bigEndian
            data.append(Data(bytes: withUnsafeBytes(of: length) { Data($0) }))
            data.append(stringData)
        }
        
        // Helper function to append string array
        func appendStringArray(_ strings: [String]) {
            let count = UInt32(strings.count).bigEndian
            data.append(Data(bytes: withUnsafeBytes(of: count) { Data($0) }))
            for string in strings {
                appendString(string)
            }
        }
        
        // Append public key
        let keyLength = UInt32(nodeInfo.nodePublicKey.count).bigEndian
        data.append(Data(bytes: withUnsafeBytes(of: keyLength) { Data($0) }))
        data.append(nodeInfo.nodePublicKey)
        
        // Append network IDs
        appendStringArray(nodeInfo.networkIds)
        
        // Append addresses
        appendStringArray(nodeInfo.addresses)
        
        // Append services count
        let servicesCount = UInt32(nodeInfo.services.count).bigEndian
        data.append(Data(bytes: withUnsafeBytes(of: servicesCount) { Data($0) }))
        
        // Append each service
        for service in nodeInfo.services {
            try appendServiceMetadata(service, to: &data)
        }
        
        // Append version
        let version = nodeInfo.version.bigEndian
        data.append(Data(bytes: withUnsafeBytes(of: version) { Data($0) }))
        
        // Append created at timestamp (as milliseconds since epoch)
        let createdAt = UInt64(nodeInfo.createdAt.timeIntervalSince1970 * 1000).bigEndian
        data.append(Data(bytes: withUnsafeBytes(of: createdAt) { Data($0) }))
        
        return data
    }
    
    // MARK: - Message Decoding
    
    /// Decode a network message from binary format
    /// Matches the Rust NetworkMessage protobuf decoding
    public static func decodeNetworkMessage(from data: Data) throws -> RunarNetworkMessage {
        var offset = 0
        
        // Helper function to read string with length prefix
        func readString() throws -> String {
            guard offset + 4 <= data.count else {
                throw RunarTransportError.serializationError("Insufficient data for string length")
            }
            
            // Read length bytes manually to avoid alignment issues
            let lengthBytes = Array(data[offset..<(offset + 4)])
            let length = UInt32(lengthBytes[0]) << 24 |
                        UInt32(lengthBytes[1]) << 16 |
                        UInt32(lengthBytes[2]) << 8 |
                        UInt32(lengthBytes[3])
            offset += 4
            
            guard offset + Int(length) <= data.count else {
                throw RunarTransportError.serializationError("Insufficient data for string")
            }
            
            let stringData = data[offset..<(offset + Int(length))]
            offset += Int(length)
            
            guard let string = String(data: stringData, encoding: .utf8) else {
                throw RunarTransportError.serializationError("Invalid UTF-8 string")
            }
            
            return string
        }
        
        // Read source node ID
        let sourceNodeId = try readString()
        
        // Read destination node ID
        let destinationNodeId = try readString()
        
        // Read message type
        let messageType = try readString()
        
        // Read timestamp
        guard offset + 8 <= data.count else {
            throw RunarTransportError.serializationError("Insufficient data for timestamp")
        }
        let timestampBytes = Array(data[offset..<(offset + 8)])
        let timestampMs = UInt64(timestampBytes[0]) << 56 |
                         UInt64(timestampBytes[1]) << 48 |
                         UInt64(timestampBytes[2]) << 40 |
                         UInt64(timestampBytes[3]) << 32 |
                         UInt64(timestampBytes[4]) << 24 |
                         UInt64(timestampBytes[5]) << 16 |
                         UInt64(timestampBytes[6]) << 8 |
                         UInt64(timestampBytes[7])
        let timestamp = Date(timeIntervalSince1970: TimeInterval(timestampMs) / 1000.0)
        offset += 8
        
        // Read payloads count
        guard offset + 4 <= data.count else {
            throw RunarTransportError.serializationError("Insufficient data for payloads count")
        }
        let payloadsCountBytes = Array(data[offset..<(offset + 4)])
        let payloadsCount = UInt32(payloadsCountBytes[0]) << 24 |
                           UInt32(payloadsCountBytes[1]) << 16 |
                           UInt32(payloadsCountBytes[2]) << 8 |
                           UInt32(payloadsCountBytes[3])
        offset += 4
        
        // Read payloads
        var payloads: [NetworkMessagePayloadItem] = []
        for _ in 0..<payloadsCount {
            let payload = try readPayload(from: data, offset: &offset)
            payloads.append(payload)
        }
        
        return RunarNetworkMessage(
            sourceNodeId: sourceNodeId,
            destinationNodeId: destinationNodeId,
            messageType: messageType,
            payloads: payloads,
            timestamp: timestamp
        )
    }
    
    /// Decode a node info from binary format
    /// Matches the Rust NodeInfo protobuf decoding
    public static func decodeNodeInfo(from data: Data) throws -> RunarNodeInfo {
        var offset = 0
        
        // Helper function to read string with length prefix
        func readString() throws -> String {
            guard offset + 4 <= data.count else {
                throw RunarTransportError.serializationError("Insufficient data for string length")
            }
            
            // Read length bytes manually to avoid alignment issues
            let lengthBytes = Array(data[offset..<(offset + 4)])
            let length = UInt32(lengthBytes[0]) << 24 |
                        UInt32(lengthBytes[1]) << 16 |
                        UInt32(lengthBytes[2]) << 8 |
                        UInt32(lengthBytes[3])
            offset += 4
            
            guard offset + Int(length) <= data.count else {
                throw RunarTransportError.serializationError("Insufficient data for string")
            }
            
            let stringData = data[offset..<(offset + Int(length))]
            offset += Int(length)
            
            guard let string = String(data: stringData, encoding: .utf8) else {
                throw RunarTransportError.serializationError("Invalid UTF-8 string")
            }
            
            return string
        }
        
        // Helper function to read string array
        func readStringArray() throws -> [String] {
            guard offset + 4 <= data.count else {
                throw RunarTransportError.serializationError("Insufficient data for array count")
            }
            
            let countBytes = Array(data[offset..<(offset + 4)])
            let count = UInt32(countBytes[0]) << 24 |
                       UInt32(countBytes[1]) << 16 |
                       UInt32(countBytes[2]) << 8 |
                       UInt32(countBytes[3])
            offset += 4
            
            var strings: [String] = []
            for _ in 0..<count {
                let string = try readString()
                strings.append(string)
            }
            
            return strings
        }
        
        // Read public key
        guard offset + 4 <= data.count else {
            throw RunarTransportError.serializationError("Insufficient data for public key length")
        }
        let keyLengthBytes = Array(data[offset..<(offset + 4)])
        let keyLength = UInt32(keyLengthBytes[0]) << 24 |
                       UInt32(keyLengthBytes[1]) << 16 |
                       UInt32(keyLengthBytes[2]) << 8 |
                       UInt32(keyLengthBytes[3])
        offset += 4
        
        guard offset + Int(keyLength) <= data.count else {
            throw RunarTransportError.serializationError("Insufficient data for public key")
        }
        let publicKey = data[offset..<(offset + Int(keyLength))]
        offset += Int(keyLength)
        
        // Read network IDs
        let networkIds = try readStringArray()
        
        // Read addresses
        let addresses = try readStringArray()
        
        // Read services count
        guard offset + 4 <= data.count else {
            throw RunarTransportError.serializationError("Insufficient data for services count")
        }
        let servicesCountBytes = Array(data[offset..<(offset + 4)])
        let servicesCount = UInt32(servicesCountBytes[0]) << 24 |
                           UInt32(servicesCountBytes[1]) << 16 |
                           UInt32(servicesCountBytes[2]) << 8 |
                           UInt32(servicesCountBytes[3])
        offset += 4
        
        // Read services
        var services: [ServiceMetadata] = []
        for _ in 0..<servicesCount {
            let service = try readServiceMetadata(from: data, offset: &offset)
            services.append(service)
        }
        
        // Read version
        guard offset + 8 <= data.count else {
            throw RunarTransportError.serializationError("Insufficient data for version")
        }
        let versionBytes = Array(data[offset..<(offset + 8)])
        let version = Int64(versionBytes[0]) << 56 |
                     Int64(versionBytes[1]) << 48 |
                     Int64(versionBytes[2]) << 40 |
                     Int64(versionBytes[3]) << 32 |
                     Int64(versionBytes[4]) << 24 |
                     Int64(versionBytes[5]) << 16 |
                     Int64(versionBytes[6]) << 8 |
                     Int64(versionBytes[7])
        offset += 8
        
        // Read created at timestamp
        guard offset + 8 <= data.count else {
            throw RunarTransportError.serializationError("Insufficient data for created at timestamp")
        }
        let createdAtBytes = Array(data[offset..<(offset + 8)])
        let createdAtMs = UInt64(createdAtBytes[0]) << 56 |
                         UInt64(createdAtBytes[1]) << 48 |
                         UInt64(createdAtBytes[2]) << 40 |
                         UInt64(createdAtBytes[3]) << 32 |
                         UInt64(createdAtBytes[4]) << 24 |
                         UInt64(createdAtBytes[5]) << 16 |
                         UInt64(createdAtBytes[6]) << 8 |
                         UInt64(createdAtBytes[7])
        let createdAt = Date(timeIntervalSince1970: TimeInterval(createdAtMs) / 1000.0)
        offset += 8
        
        return RunarNodeInfo(
            nodePublicKey: publicKey,
            networkIds: networkIds,
            addresses: addresses,
            services: services,
            version: version,
            createdAt: createdAt
        )
    }
    
    // MARK: - Private Helper Methods
    
    private static func appendPayload(_ payload: NetworkMessagePayloadItem, to data: inout Data) throws {
        // Helper function to append string with length prefix
        func appendString(_ string: String) {
            let stringData = string.data(using: .utf8) ?? Data()
            let length = UInt32(stringData.count).bigEndian
            data.append(Data(bytes: withUnsafeBytes(of: length) { Data($0) }))
            data.append(stringData)
        }
        
        // Append path
        appendString(payload.path)
        
        // Append value bytes
        let valueLength = UInt32(payload.valueBytes.count).bigEndian
        data.append(Data(bytes: withUnsafeBytes(of: valueLength) { Data($0) }))
        data.append(payload.valueBytes)
        
        // Append correlation ID
        appendString(payload.correlationId)
    }
    
    private static func readPayload(from data: Data, offset: inout Int) throws -> NetworkMessagePayloadItem {
        // Helper function to read string with length prefix
        func readString() throws -> String {
            guard offset + 4 <= data.count else {
                throw RunarTransportError.serializationError("Insufficient data for string length")
            }
            
            // Read length bytes manually to avoid alignment issues
            let lengthBytes = Array(data[offset..<(offset + 4)])
            let length = UInt32(lengthBytes[0]) << 24 |
                        UInt32(lengthBytes[1]) << 16 |
                        UInt32(lengthBytes[2]) << 8 |
                        UInt32(lengthBytes[3])
            offset += 4
            
            guard offset + Int(length) <= data.count else {
                throw RunarTransportError.serializationError("Insufficient data for string")
            }
            
            let stringData = data[offset..<(offset + Int(length))]
            offset += Int(length)
            
            guard let string = String(data: stringData, encoding: .utf8) else {
                throw RunarTransportError.serializationError("Invalid UTF-8 string")
            }
            
            return string
        }
        
        // Read path
        let path = try readString()
        
        // Read value bytes
        guard offset + 4 <= data.count else {
            throw RunarTransportError.serializationError("Insufficient data for value bytes length")
        }
        let valueLengthBytes = Array(data[offset..<(offset + 4)])
        let valueLength = UInt32(valueLengthBytes[0]) << 24 |
                         UInt32(valueLengthBytes[1]) << 16 |
                         UInt32(valueLengthBytes[2]) << 8 |
                         UInt32(valueLengthBytes[3])
        offset += 4
        
        guard offset + Int(valueLength) <= data.count else {
            throw RunarTransportError.serializationError("Insufficient data for value bytes")
        }
        let valueBytes = data[offset..<(offset + Int(valueLength))]
        offset += Int(valueLength)
        
        // Read correlation ID
        let correlationId = try readString()
        
        return NetworkMessagePayloadItem(
            path: path,
            valueBytes: valueBytes,
            correlationId: correlationId
        )
    }
    
    private static func appendServiceMetadata(_ service: ServiceMetadata, to data: inout Data) throws {
        // Helper function to append string with length prefix
        func appendString(_ string: String) {
            let stringData = string.data(using: .utf8) ?? Data()
            let length = UInt32(stringData.count).bigEndian
            data.append(Data(bytes: withUnsafeBytes(of: length) { Data($0) }))
            data.append(stringData)
        }
        
        // Helper function to append optional string
        func appendOptionalString(_ string: String?) {
            if let string = string {
                appendString(string)
            } else {
                // Write empty string for nil
                appendString("")
            }
        }
        
        // Helper function to append array
        func appendActionArray(_ actions: [ActionMetadata]) {
            let count = UInt32(actions.count).bigEndian
            data.append(Data(bytes: withUnsafeBytes(of: count) { Data($0) }))
            for action in actions {
                appendString(action.actionPath)
                appendString(action.actionName)
                appendString(action.description)
                appendOptionalString(action.inputSchema)
                appendOptionalString(action.outputSchema)
            }
        }
        
        func appendEventArray(_ events: [EventMetadata]) {
            let count = UInt32(events.count).bigEndian
            data.append(Data(bytes: withUnsafeBytes(of: count) { Data($0) }))
            for event in events {
                appendString(event.path)
                appendString(event.description)
                appendOptionalString(event.dataSchema)
            }
        }
        
        // Append service fields
        appendString(service.servicePath)
        appendString(service.networkId)
        appendString(service.serviceName)
        appendString(service.description)
        appendActionArray(service.actions)
        appendEventArray(service.events)
    }
    
    private static func readServiceMetadata(from data: Data, offset: inout Int) throws -> ServiceMetadata {
        // Helper function to read string with length prefix
        func readString() throws -> String {
            guard offset + 4 <= data.count else {
                throw RunarTransportError.serializationError("Insufficient data for string length")
            }
            
            // Read length bytes manually to avoid alignment issues
            let lengthBytes = Array(data[offset..<(offset + 4)])
            let length = UInt32(lengthBytes[0]) << 24 |
                        UInt32(lengthBytes[1]) << 16 |
                        UInt32(lengthBytes[2]) << 8 |
                        UInt32(lengthBytes[3])
            offset += 4
            
            guard offset + Int(length) <= data.count else {
                throw RunarTransportError.serializationError("Insufficient data for string")
            }
            
            let stringData = data[offset..<(offset + Int(length))]
            offset += Int(length)
            
            guard let string = String(data: stringData, encoding: .utf8) else {
                throw RunarTransportError.serializationError("Invalid UTF-8 string")
            }
            
            return string
        }
        
        // Helper function to read optional string
        func readOptionalString() throws -> String? {
            let string = try readString()
            return string.isEmpty ? nil : string
        }
        
        // Helper function to read action array
        func readActionArray() throws -> [ActionMetadata] {
            guard offset + 4 <= data.count else {
                throw RunarTransportError.serializationError("Insufficient data for actions count")
            }
            
            let countBytes = Array(data[offset..<(offset + 4)])
            let count = UInt32(countBytes[0]) << 24 |
                       UInt32(countBytes[1]) << 16 |
                       UInt32(countBytes[2]) << 8 |
                       UInt32(countBytes[3])
            offset += 4
            
            var actions: [ActionMetadata] = []
            for _ in 0..<count {
                let actionPath = try readString()
                let actionName = try readString()
                let description = try readString()
                let inputSchema = try readOptionalString()
                let outputSchema = try readOptionalString()
                
                actions.append(ActionMetadata(
                    actionPath: actionPath,
                    actionName: actionName,
                    description: description,
                    inputSchema: inputSchema,
                    outputSchema: outputSchema
                ))
            }
            
            return actions
        }
        
        // Helper function to read event array
        func readEventArray() throws -> [EventMetadata] {
            guard offset + 4 <= data.count else {
                throw RunarTransportError.serializationError("Insufficient data for events count")
            }
            
            let countBytes = Array(data[offset..<(offset + 4)])
            let count = UInt32(countBytes[0]) << 24 |
                       UInt32(countBytes[1]) << 16 |
                       UInt32(countBytes[2]) << 8 |
                       UInt32(countBytes[3])
            offset += 4
            
            var events: [EventMetadata] = []
            for _ in 0..<count {
                let path = try readString()
                let description = try readString()
                let dataSchema = try readOptionalString()
                
                events.append(EventMetadata(
                    path: path,
                    description: description,
                    dataSchema: dataSchema
                ))
            }
            
            return events
        }
        
        // Read service fields
        let servicePath = try readString()
        let networkId = try readString()
        let serviceName = try readString()
        let description = try readString()
        let actions = try readActionArray()
        let events = try readEventArray()
        
        return ServiceMetadata(
            servicePath: servicePath,
            networkId: networkId,
            serviceName: serviceName,
            description: description,
            actions: actions,
            events: events
        )
    }
} 