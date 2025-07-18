import Foundation
import SwiftProtobuf

/// Protobuf message definitions that match the Rust multicast discovery protocol
/// These must be identical to the Rust PeerInfo and MulticastMessage structures

// MARK: - PeerInfo (matches Rust PeerInfo)
@available(macOS 12.0, iOS 15.0, *)
public struct DiscoveryPeerInfo: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
    public var publicKey: Data = Data()
    public var addresses: [String] = []
    
    public var unknownFields = SwiftProtobuf.UnknownStorage()
    
    public init() {}
    
    public init(publicKey: Data, addresses: [String]) {
        self.publicKey = publicKey
        self.addresses = addresses
    }
    
    public static let protoMessageName: String = "DiscoveryPeerInfo"
    public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
        1: .same(proto: "public_key"),
        2: .same(proto: "addresses")
    ]
    
    public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
        while let fieldNumber = try decoder.nextFieldNumber() {
            switch fieldNumber {
            case 1: try decoder.decodeSingularBytesField(value: &publicKey)
            case 2: try decoder.decodeRepeatedStringField(value: &addresses)
            default: break
            }
        }
    }
    
    public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
        if !publicKey.isEmpty {
            try visitor.visitSingularBytesField(value: publicKey, fieldNumber: 1)
        }
        if !addresses.isEmpty {
            try visitor.visitRepeatedStringField(value: addresses, fieldNumber: 2)
        }
        try unknownFields.traverse(visitor: &visitor)
    }
    
    public static func == (lhs: DiscoveryPeerInfo, rhs: DiscoveryPeerInfo) -> Bool {
        if lhs.publicKey != rhs.publicKey { return false }
        if lhs.addresses != rhs.addresses { return false }
        if lhs.unknownFields != rhs.unknownFields { return false }
        return true
    }
}

// MARK: - MulticastMessage (matches Rust MulticastMessage)
@available(macOS 12.0, iOS 15.0, *)
public struct DiscoveryMulticastMessage: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
    public var announce: DiscoveryPeerInfo? {
        get { return _announce }
        set { _announce = newValue }
    }
    public var goodbye: String {
        get { return _goodbye ?? "" }
        set { _goodbye = newValue }
    }
    
    public var unknownFields = SwiftProtobuf.UnknownStorage()
    
    public init() {}
    
    public init(announce: DiscoveryPeerInfo? = nil, goodbye: String = "") {
        self._announce = announce
        self._goodbye = goodbye
    }
    
    private var _announce: DiscoveryPeerInfo?
    private var _goodbye: String?
    
    public static let protoMessageName: String = "DiscoveryMulticastMessage"
    public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
        1: .same(proto: "announce"),
        2: .same(proto: "goodbye")
    ]
    
    public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
        while let fieldNumber = try decoder.nextFieldNumber() {
            switch fieldNumber {
            case 1: try decoder.decodeSingularMessageField(value: &_announce)
            case 2: try decoder.decodeSingularStringField(value: &_goodbye)
            default: break
            }
        }
    }
    
    public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
        if let v = _announce {
            try visitor.visitSingularMessageField(value: v, fieldNumber: 1)
        }
        if let v = _goodbye {
            try visitor.visitSingularStringField(value: v, fieldNumber: 2)
        }
        try unknownFields.traverse(visitor: &visitor)
    }
    
    public static func == (lhs: DiscoveryMulticastMessage, rhs: DiscoveryMulticastMessage) -> Bool {
        if lhs._announce != rhs._announce { return false }
        if lhs._goodbye != rhs._goodbye { return false }
        if lhs.unknownFields != rhs.unknownFields { return false }
        return true
    }
}

// MARK: - Helper Extensions
@available(macOS 12.0, iOS 15.0, *)
extension DiscoveryMulticastMessage {
    /// Get the sender ID from the message (matches Rust sender_id() method)
    func senderId() -> String? {
        if let announce = announce {
            return NodeUtils.compactId(from: announce.publicKey)
        } else if !goodbye.isEmpty {
            return goodbye
        }
        return nil
    }
} 