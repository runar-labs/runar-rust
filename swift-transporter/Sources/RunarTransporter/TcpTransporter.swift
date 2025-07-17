import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import Logging
import AsyncAlgorithms

// MARK: - TCP Transport Implementation

/// Real TCP-based transport implementation for the Runar network
@available(macOS 10.15, iOS 13.0, *)
public final class TcpTransporter: TransportProtocol, @unchecked Sendable {
    private let nodeInfo: RunarNodeInfo
    internal let logger: Logger
    private let bindAddress: String
    private let messageHandler: MessageHandlerProtocol
    
    private var running = false
    private var peerNodeIds: Set<String> = []
    private let peerUpdateStream: AsyncStream<RunarNodeInfo>
    private let peerUpdateContinuation: AsyncStream<RunarNodeInfo>.Continuation
    
    private let eventLoopGroup: EventLoopGroup
    private var serverChannel: Channel?
    private var clientChannels: [String: Channel] = [:]
    private let clientChannelsLock = NSLock()
    
    public init(
        nodeInfo: RunarNodeInfo,
        bindAddress: String,
        messageHandler: MessageHandlerProtocol,
        logger: Logger
    ) {
        self.nodeInfo = nodeInfo
        self.bindAddress = bindAddress
        self.messageHandler = messageHandler
        self.logger = logger
        self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        
        var continuation: AsyncStream<RunarNodeInfo>.Continuation!
        self.peerUpdateStream = AsyncStream<RunarNodeInfo> { c in continuation = c }
        self.peerUpdateContinuation = continuation
        
        logger.info("TcpTransporter initialized for node: \(nodeInfo.nodeId) on \(bindAddress)")
    }
    
    deinit {
        try? eventLoopGroup.syncShutdownGracefully()
    }
    
    // MARK: - TransportProtocol Implementation
    
    public func start() async throws {
        guard !running else { return }
        
        logger.info("Starting TCP transport on \(bindAddress)")
        
        let bootstrap = ServerBootstrap(group: eventLoopGroup)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { [weak self] channel in
                guard let self = self else { return channel.eventLoop.makeFailedFuture(TransportError.transportNotRunning) }
                return channel.pipeline.addHandler(TcpMessageHandler(transporter: self))
            }
            .childChannelOption(ChannelOptions.socketOption(.so_keepalive), value: 1)
            .childChannelOption(ChannelOptions.socketOption(.tcp_nodelay), value: 1)
        
        // Parse bind address properly
        let address = try parseSocketAddress(bindAddress)
        serverChannel = try await bootstrap.bind(to: address).get()
        
        running = true
        logger.info("TCP transport started successfully on \(serverChannel?.localAddress?.description ?? "unknown")")
    }
    
    public func stop() async throws {
        guard running else { return }
        
        logger.info("Stopping TCP transport")
        
        // Close server channel
        if let serverChannel = serverChannel {
            try await serverChannel.close()
            self.serverChannel = nil
        }
        
        // Close all client channels
        let channels: [Channel]
        clientChannelsLock.lock()
        channels = Array(clientChannels.values)
        clientChannels.removeAll()
        clientChannelsLock.unlock()
        
        for channel in channels {
            try await channel.close()
        }
        
        running = false
        logger.info("TCP transport stopped")
    }
    
    public func connect(to peerInfo: RunarPeerInfo) async throws {
        let peerNodeId = peerInfo.publicKey.base64EncodedString()
        
        guard running else {
            throw TransportError.transportNotRunning
        }
        
        // Check if already connected
        let alreadyConnected: Bool
        clientChannelsLock.lock()
        alreadyConnected = clientChannels[peerNodeId] != nil
        clientChannelsLock.unlock()
        
        if alreadyConnected {
            logger.info("Already connected to peer: \(peerNodeId)")
            return
        }
        
        logger.info("Connecting to peer: \(peerNodeId) at \(peerInfo.addresses.first ?? "unknown")")
        
        // Try to connect to the first available address
        for addressString in peerInfo.addresses {
            do {
                let address = try parseSocketAddress(addressString)
                let channel = try await connectToAddress(address, peerNodeId: peerNodeId)
                
                clientChannelsLock.lock()
                clientChannels[peerNodeId] = channel
                clientChannelsLock.unlock()
                
                peerNodeIds.insert(peerNodeId)
                logger.info("Successfully connected to peer: \(peerNodeId)")
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
        
        let channel: Channel?
        clientChannelsLock.lock()
        channel = clientChannels.removeValue(forKey: peerNodeId)
        clientChannelsLock.unlock()
        
        if let channel = channel {
            try await channel.close()
        }
        
        peerNodeIds.remove(peerNodeId)
        logger.info("Disconnected from peer: \(peerNodeId)")
    }
    
    public func isConnected(to peerNodeId: String) async -> Bool {
        clientChannelsLock.lock()
        let isConnected = clientChannels[peerNodeId] != nil
        clientChannelsLock.unlock()
        return isConnected
    }
    
    public func send(_ message: RunarNetworkMessage) async throws {
        guard running else {
            throw TransportError.transportNotRunning
        }
        
        let peerNodeId = message.destinationNodeId
        
        let channel: Channel?
        clientChannelsLock.lock()
        channel = clientChannels[peerNodeId]
        clientChannelsLock.unlock()
        
        guard let channel = channel else {
            throw TransportError.peerNotConnected(peerNodeId)
        }
        
        logger.info("Sending message to \(peerNodeId): \(message.messageType)")
        
        // Serialize message
        let encoder = JSONEncoder()
        let messageData = try encoder.encode(message)
        
        // Send message length first (4 bytes), then message data
        var buffer = channel.allocator.buffer(capacity: 4 + messageData.count)
        buffer.writeInteger(UInt32(messageData.count), endianness: .big)
        buffer.writeBytes(messageData)
        
        try await channel.writeAndFlush(buffer)
        logger.info("Message sent successfully to \(peerNodeId)")
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
    
    private func connectToAddress(_ address: SocketAddress, peerNodeId: String) async throws -> Channel {
        let bootstrap = ClientBootstrap(group: eventLoopGroup)
            .channelInitializer { [weak self] channel in
                guard let self = self else { return channel.eventLoop.makeFailedFuture(TransportError.transportNotRunning) }
                return channel.pipeline.addHandler(TcpMessageHandler(transporter: self))
            }
            .channelOption(ChannelOptions.socketOption(.so_keepalive), value: 1)
            .channelOption(ChannelOptions.socketOption(.tcp_nodelay), value: 1)
        
        return try await bootstrap.connect(to: address).get()
    }
    
    internal func handleIncomingMessage(_ message: RunarNetworkMessage) async {
        logger.info("Received message from \(message.sourceNodeId): \(message.messageType)")
        
        do {
            try await messageHandler.handle(message)
        } catch {
            logger.error("Error handling message: \(error)")
        }
    }
}

// MARK: - TCP Message Handler

@available(macOS 10.15, iOS 13.0, *)
private final class TcpMessageHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    
    private let transporter: TcpTransporter
    private var messageBuffer = ByteBuffer()
    
    init(transporter: TcpTransporter) {
        self.transporter = transporter
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        messageBuffer.writeBuffer(&buffer)
        
        // Process complete messages
        while messageBuffer.readableBytes >= 4 {
            // Read message length
            guard let messageLength = messageBuffer.readInteger(endianness: .big, as: UInt32.self) else {
                break
            }
            
            // Check if we have the complete message
            guard messageBuffer.readableBytes >= messageLength else {
                // Put the length back and wait for more data
                messageBuffer.moveReaderIndex(to: messageBuffer.readerIndex - 4)
                break
            }
            
            // Read the message data
            guard let messageData = messageBuffer.readBytes(length: Int(messageLength)) else {
                break
            }
            
            // Decode and handle the message
            Task {
                do {
                    let decoder = JSONDecoder()
                    let message = try decoder.decode(RunarNetworkMessage.self, from: Data(messageData))
                    await transporter.handleIncomingMessage(message)
                } catch {
                    transporter.logger.error("Failed to decode message: \(error)")
                }
            }
        }
    }
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        transporter.logger.error("Channel error: \(error)")
        context.close(promise: nil)
    }
}

// MARK: - Transport Errors

public enum TransportError: Error, LocalizedError {
    case transportNotRunning
    case connectionFailed(String)
    case peerNotConnected(String)
    case serializationError(String)
    
    public var errorDescription: String? {
        switch self {
        case .transportNotRunning:
            return "Transport is not running"
        case .connectionFailed(let reason):
            return "Connection failed: \(reason)"
        case .peerNotConnected(let peerId):
            return "Peer not connected: \(peerId)"
        case .serializationError(let reason):
            return "Serialization error: \(reason)"
        }
    }
} 