import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import Logging
import AsyncAlgorithms
import Crypto

// MARK: - QUIC-like Transport Implementation

/// QUIC-like transport implementation for the Runar network
/// Uses UDP with custom QUIC-like framing to mimic the Rust quic_transport.rs implementation
@available(macOS 10.15, iOS 13.0, *)
public final class QuicTransporter: TransportProtocol, @unchecked Sendable {
    private let nodeInfo: RunarNodeInfo
    let logger: Logger // Changed to internal for access by QuicMessageHandler
    private let bindAddress: String
    private let messageHandler: MessageHandlerProtocol
    private let options: QuicTransportOptions
    
    private var running = false
    private var peerNodeIds: Set<String> = []
    private let peerUpdateStream: AsyncStream<RunarNodeInfo>
    private let peerUpdateContinuation: AsyncStream<RunarNodeInfo>.Continuation
    
    private let eventLoopGroup: EventLoopGroup
    private var serverChannel: Channel?
    private var peerChannels: [String: Channel] = [:]
    private let peerChannelsLock = NSLock()
    
    // Stream management for request-response patterns (QUIC-like)
    private var bidirectionalStreams: [String: StreamState] = [:]
    private var streamCorrelations: [String: StreamCorrelation] = [:]
    private let streamsLock = NSLock()
    
    public init(
        nodeInfo: RunarNodeInfo,
        bindAddress: String,
        messageHandler: MessageHandlerProtocol,
        options: QuicTransportOptions,
        logger: Logger
    ) {
        self.nodeInfo = nodeInfo
        self.bindAddress = bindAddress
        self.messageHandler = messageHandler
        self.options = options
        self.logger = logger
        self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        
        var continuation: AsyncStream<RunarNodeInfo>.Continuation!
        self.peerUpdateStream = AsyncStream<RunarNodeInfo> { c in continuation = c }
        self.peerUpdateContinuation = continuation
        
        logger.info("QuicTransporter initialized for node: \(nodeInfo.nodeId) on \(bindAddress)")
    }
    
    deinit {
        try? eventLoopGroup.syncShutdownGracefully()
    }
    
    // MARK: - TransportProtocol Implementation
    
    public func start() async throws {
        guard !running else { return }
        
        logger.info("Starting QUIC-like transport on \(bindAddress)")
        
        // Parse bind address
        let address = try parseSocketAddress(bindAddress)
        
        // Create UDP bootstrap for QUIC-like transport
        let bootstrap = DatagramBootstrap(group: eventLoopGroup)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { [weak self] channel in
                guard let self = self else { return channel.eventLoop.makeFailedFuture(TransportError.transportNotRunning) }
                return channel.pipeline.addHandler(QuicMessageHandler(transporter: self))
            }
        
        serverChannel = try await bootstrap.bind(to: address).get()
        running = true
        
        logger.info("QUIC-like transport started successfully on \(address)")
    }
    
    public func stop() async throws {
        guard running else { return }
        
        logger.info("Stopping QUIC-like transport")
        
        // Close server channel
        if let serverChannel = serverChannel {
            try await serverChannel.close()
            self.serverChannel = nil
        }
        
        // Close all peer channels
        let channels: [Channel] = await withCheckedContinuation { continuation in
            peerChannelsLock.lock()
            let chs = Array(peerChannels.values)
            peerChannels.removeAll()
            peerChannelsLock.unlock()
            continuation.resume(returning: chs)
        }
        
        for channel in channels {
            try await channel.close()
        }
        
        running = false
        logger.info("QUIC-like transport stopped")
    }
    
    public func connect(to peerInfo: RunarPeerInfo) async throws {
        let peerNodeId = peerInfo.publicKey.base64EncodedString()
        
        guard running else {
            throw TransportError.transportNotRunning
        }
        
        // Check if already connected
        let alreadyConnected: Bool = await withCheckedContinuation { continuation in
            peerChannelsLock.lock()
            let connected = peerChannels[peerNodeId] != nil
            peerChannelsLock.unlock()
            continuation.resume(returning: connected)
        }
        
        if alreadyConnected {
            logger.info("Already connected to peer: \(peerNodeId)")
            return
        }
        
        logger.info("Connecting to peer: \(peerNodeId) at \(peerInfo.addresses.first ?? "unknown")")
        
        // Try to connect to the first available address
        for addressString in peerInfo.addresses {
            do {
                let address = try parseSocketAddress(addressString)
                let channel = try await connectToPeer(address, peerNodeId: peerNodeId)
                
                await withCheckedContinuation { continuation in
                    peerChannelsLock.lock()
                    peerChannels[peerNodeId] = channel
                    peerChannelsLock.unlock()
                    continuation.resume()
                }
                
                peerNodeIds.insert(peerNodeId)
                logger.info("Successfully connected to peer: \(peerNodeId)")
                
                // Perform handshake
                try await performHandshake(channel: channel, peerNodeId: peerNodeId)
                
                return
            } catch {
                logger.warning("Failed to connect to \(addressString): \(error)")
                continue
            }
        }
        
        throw TransportError.connectionFailed("Failed to connect to any address for peer: \(peerNodeId)")
    }
    
    public func disconnect(from peerNodeId: String) async throws {
        logger.info("Disconnecting from peer: \(peerNodeId)")
        
        let channel: Channel? = await withCheckedContinuation { continuation in
            peerChannelsLock.lock()
            let ch = peerChannels.removeValue(forKey: peerNodeId)
            peerChannelsLock.unlock()
            continuation.resume(returning: ch)
        }
        
        if let channel = channel {
            try await channel.close()
        }
        
        peerNodeIds.remove(peerNodeId)
        logger.info("Disconnected from peer: \(peerNodeId)")
    }
    
    public func isConnected(to peerNodeId: String) async -> Bool {
        await withCheckedContinuation { continuation in
            peerChannelsLock.lock()
            let isConnected = peerChannels[peerNodeId] != nil
            peerChannelsLock.unlock()
            continuation.resume(returning: isConnected)
        }
    }
    
    public func send(_ message: RunarNetworkMessage) async throws {
        guard running else {
            throw TransportError.transportNotRunning
        }
        
        let peerNodeId = message.destinationNodeId
        let messagePattern = classifyMessagePattern(message)
        
        logger.info("Sending message to \(peerNodeId): \(message.messageType) (Pattern: \(messagePattern))")
        
        let channel: Channel? = await withCheckedContinuation { continuation in
            peerChannelsLock.lock()
            let ch = peerChannels[peerNodeId]
            peerChannelsLock.unlock()
            continuation.resume(returning: ch)
        }
        
        guard let channel = channel else {
            throw TransportError.peerNotConnected(peerNodeId)
        }
        
        switch messagePattern {
        case .oneWay:
            try await sendOneWayMessage(channel: channel, message: message)
        case .requestResponse:
            try await sendRequestMessage(channel: channel, message: message)
        case .response:
            try await sendResponseMessage(channel: channel, message: message)
        }
    }
    
    public func updatePeers(with nodeInfo: RunarNodeInfo) async throws {
        logger.info("Updating peers with node info: \(nodeInfo.nodeId)")
        peerUpdateContinuation.yield(nodeInfo)
    }
    
    public var localAddress: String {
        bindAddress
    }
    
    public func subscribeToPeerUpdates() -> AsyncStream<RunarNodeInfo> {
        peerUpdateStream
    }
    
    // MARK: - Private Methods
    
    private func parseSocketAddress(_ addressString: String) throws -> SocketAddress {
        let components = addressString.split(separator: ":")
        guard components.count == 2,
              let port = Int(components[1]) else {
            throw TransportError.serializationError("Invalid address format: \(addressString). Expected format: ip:port")
        }
        
        let ipString = String(components[0])
        return try SocketAddress(ipAddress: ipString, port: port)
    }
    
    private func connectToPeer(_ address: SocketAddress, peerNodeId: String) async throws -> Channel {
        // Create UDP bootstrap for client connection
        let bootstrap = DatagramBootstrap(group: eventLoopGroup)
            .channelInitializer { [weak self] channel in
                guard let self = self else { return channel.eventLoop.makeFailedFuture(TransportError.transportNotRunning) }
                return channel.pipeline.addHandler(QuicMessageHandler(transporter: self))
            }
        
        return try await bootstrap.connect(to: address).get()
    }
    
    private func performHandshake(channel: Channel, peerNodeId: String) async throws {
        // Create handshake message
        let handshakeMessage = RunarNetworkMessage(
            sourceNodeId: nodeInfo.nodeId,
            destinationNodeId: peerNodeId,
            messageType: "NODE_INFO_HANDSHAKE",
            payloads: [
                NetworkMessagePayloadItem(
                    path: "",
                    valueBytes: try JSONEncoder().encode(nodeInfo),
                    correlationId: UUID().uuidString
                )
            ],
            timestamp: Date()
        )
        
        // Send handshake via one-way message
        try await sendOneWayMessage(channel: channel, message: handshakeMessage)
        
        logger.info("Handshake sent to peer: \(peerNodeId)")
    }
    
    private func sendOneWayMessage(channel: Channel, message: RunarNetworkMessage) async throws {
        // Create QUIC-like packet with unidirectional stream
        let packet = QuicPacket(
            streamType: .unidirectional,
            streamId: generateStreamId(),
            message: message
        )
        
        // Serialize and send packet
        let packetData = try serializePacket(packet)
        var buffer = channel.allocator.buffer(capacity: packetData.count)
        buffer.writeBytes(packetData)
        
        try await channel.writeAndFlush(buffer)
        logger.info("One-way message sent successfully")
    }
    
    private func sendRequestMessage(channel: Channel, message: RunarNetworkMessage) async throws {
        // Create QUIC-like packet with bidirectional stream
        let streamId = generateStreamId()
        let packet = QuicPacket(
            streamType: .bidirectional,
            streamId: streamId,
            message: message
        )
        
        // Store stream for response
        if let payload = message.payloads.first {
            await withCheckedContinuation { continuation in
                streamsLock.lock()
                bidirectionalStreams[payload.correlationId] = StreamState(
                    streamId: streamId,
                    channel: channel,
                    createdAt: Date()
                )
                streamsLock.unlock()
                continuation.resume()
            }
        }
        
        // Serialize and send packet
        let packetData = try serializePacket(packet)
        var buffer = channel.allocator.buffer(capacity: packetData.count)
        buffer.writeBytes(packetData)
        
        try await channel.writeAndFlush(buffer)
        logger.info("Request message sent successfully")
    }
    
    private func sendResponseMessage(channel: Channel, message: RunarNetworkMessage) async throws {
        // Find the original request stream
        guard let payload = message.payloads.first else {
            throw TransportError.serializationError("Response message missing correlation ID")
        }
        
        let streamState: StreamState? = await withCheckedContinuation { continuation in
            streamsLock.lock()
            let state = bidirectionalStreams.removeValue(forKey: payload.correlationId)
            streamCorrelations.removeValue(forKey: payload.correlationId)
            streamsLock.unlock()
            continuation.resume(returning: state)
        }
        
        guard let streamState = streamState else {
            throw TransportError.serializationError("No stream found for correlation ID: \(payload.correlationId)")
        }
        
        // Create QUIC-like packet with response on the same stream
        let packet = QuicPacket(
            streamType: .bidirectional,
            streamId: streamState.streamId,
            message: message
        )
        
        // Serialize and send packet
        let packetData = try serializePacket(packet)
        var buffer = streamState.channel.allocator.buffer(capacity: packetData.count)
        buffer.writeBytes(packetData)
        
        try await streamState.channel.writeAndFlush(buffer)
        logger.info("Response message sent successfully")
    }
    
    private func classifyMessagePattern(_ message: RunarNetworkMessage) -> MessagePattern {
        switch message.messageType {
        case "Handshake", "Discovery", "Announcement", "Heartbeat":
            return .oneWay
        case "Request":
            return .requestResponse
        case "Response", "Error":
            return .response
        default:
            logger.warning("Unknown message type '\(message.messageType)', treating as one-way")
            return .oneWay
        }
    }
    
    private func generateStreamId() -> UInt64 {
        return UInt64.random(in: 1...UInt64.max)
    }
    
    private func serializePacket(_ packet: QuicPacket) throws -> Data {
        let encoder = JSONEncoder()
        return try encoder.encode(packet)
    }
    
    internal func handleIncomingPacket(_ packet: QuicPacket, from address: SocketAddress) async {
        logger.info("Received packet from \(address): Stream \(packet.streamId), Type: \(packet.streamType)")
        
        // Handle handshake messages
        if packet.message.messageType == "NODE_INFO_HANDSHAKE" {
            try? await processHandshakeMessage(packet.message)
            return
        }
        
        // Handle regular messages
        await handleIncomingMessage(packet.message)
    }
    
    private func processHandshakeMessage(_ message: RunarNetworkMessage) async throws {
        if message.messageType == "NODE_INFO_HANDSHAKE" {
            // Extract node info from payload
            if let payload = message.payloads.first {
                let decoder = JSONDecoder()
                let peerNodeInfo = try decoder.decode(RunarNodeInfo.self, from: Data(payload.valueBytes))
                
                // Send handshake response
                let response = RunarNetworkMessage(
                    sourceNodeId: nodeInfo.nodeId,
                    destinationNodeId: message.sourceNodeId,
                    messageType: "NODE_INFO_HANDSHAKE_RESPONSE",
                    payloads: [
                        NetworkMessagePayloadItem(
                            path: payload.path,
                            valueBytes: try JSONEncoder().encode(nodeInfo),
                            correlationId: payload.correlationId
                        )
                    ],
                    timestamp: Date()
                )
                
                // Send response via one-way message
                let channel: Channel? = await withCheckedContinuation { continuation in
                    peerChannelsLock.lock()
                    let ch = peerChannels[message.sourceNodeId]
                    peerChannelsLock.unlock()
                    continuation.resume(returning: ch)
                }
                
                if let channel = channel {
                    try await sendOneWayMessage(channel: channel, message: response)
                }
                
                // Send peer update
                peerUpdateContinuation.yield(peerNodeInfo)
            }
        }
    }
    
    private func handleIncomingMessage(_ message: RunarNetworkMessage) async {
        logger.info("Received message from \(message.sourceNodeId): \(message.messageType)")
        
        do {
            try await messageHandler.handle(message)
        } catch {
            logger.error("Error handling message: \(error)")
        }
    }
}

// MARK: - Supporting Types

@available(macOS 10.15, iOS 13.0, *)
private enum MessagePattern {
    case oneWay
    case requestResponse
    case response
}

@available(macOS 10.15, iOS 13.0, *)
internal enum StreamType: String, Codable {
    case unidirectional
    case bidirectional
}

@available(macOS 10.15, iOS 13.0, *)
internal struct QuicPacket: Codable { // Changed to internal for access by QuicMessageHandler
    let streamType: StreamType
    let streamId: UInt64
    let message: RunarNetworkMessage
}

@available(macOS 10.15, iOS 13.0, *)
private struct StreamState {
    let streamId: UInt64
    let channel: Channel
    let createdAt: Date
}

@available(macOS 10.15, iOS 13.0, *)
private struct StreamCorrelation {
    let peerNodeId: String
    let streamId: UInt64
    let correlationId: String
    let createdAt: Date
}

@available(macOS 10.15, iOS 13.0, *)
public struct QuicTransportOptions {
    public let verifyCertificates: Bool
    public let keepAliveInterval: TimeInterval
    public let connectionIdleTimeout: TimeInterval
    public let streamIdleTimeout: TimeInterval
    public let maxIdleStreamsPerPeer: Int
    public let certificates: [NIOSSLCertificate]?
    public let privateKey: NIOSSLPrivateKey?
    public let rootCertificates: [NIOSSLCertificate]?
    
    public init(
        verifyCertificates: Bool = true,
        keepAliveInterval: TimeInterval = 15,
        connectionIdleTimeout: TimeInterval = 60,
        streamIdleTimeout: TimeInterval = 30,
        maxIdleStreamsPerPeer: Int = 100,
        certificates: [NIOSSLCertificate]? = nil,
        privateKey: NIOSSLPrivateKey? = nil,
        rootCertificates: [NIOSSLCertificate]? = nil
    ) {
        self.verifyCertificates = verifyCertificates
        self.keepAliveInterval = keepAliveInterval
        self.connectionIdleTimeout = connectionIdleTimeout
        self.streamIdleTimeout = streamIdleTimeout
        self.maxIdleStreamsPerPeer = maxIdleStreamsPerPeer
        self.certificates = certificates
        self.privateKey = privateKey
        self.rootCertificates = rootCertificates
    }
}

// MARK: - QUIC Message Handler

@available(macOS 10.15, iOS 13.0, *)
private final class QuicMessageHandler: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>
    
    private let transporter: QuicTransporter
    
    init(transporter: QuicTransporter) {
        self.transporter = transporter
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        let buffer = envelope.data
        
        // Parse QUIC-like packet
        do {
            let packetData = Data(buffer.readableBytesView)
            let decoder = JSONDecoder()
            let packet = try decoder.decode(QuicPacket.self, from: packetData)
            
            // Handle packet
            Task {
                await transporter.handleIncomingPacket(packet, from: envelope.remoteAddress)
            }
        } catch {
            transporter.logger.error("Failed to decode QUIC packet: \(error)")
        }
    }
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        transporter.logger.error("Channel error: \(error)")
        context.close(promise: nil)
    }
} 