// This file has been renamed to QuicTransporter_old.swift for reference only.
// Please use NetworkQuicTransporter.swift for all new QUIC transport logic.

import Foundation
import os.log

#if canImport(Network)
import Network
#endif

/// QUIC-like transport implementation
/// Uses Network.framework on Apple platforms, simple implementation on Linux
public class QuicTransporter {
    // MARK: - Properties
    
    private let nodeId: String
    private let bindAddress: String
    private let port: UInt16
    private let logger: Logger
    private let messageHandler: (RunarNetworkMessage) -> Void
    
    #if canImport(Network)
    // Network.framework implementation for Apple platforms
    private var listener: NWListener?
    private var connections: [String: NWConnection] = [:]
    private let connectionQueue = DispatchQueue(label: "com.runar.connection", qos: .userInitiated)
    #else
    // Simple implementation for Linux testing
    private var isListening = false
    private var connectedPeers: Set<String> = []
    private let stateQueue = DispatchQueue(label: "com.runar.state", qos: .userInitiated)
    #endif
    
    private let messageQueue = DispatchQueue(label: "com.runar.message", qos: .userInitiated)
    
    // State management
    private var isRunning = false
    private let stateQueue = DispatchQueue(label: "com.runar.state", qos: .userInitiated)
    
    // MARK: - Initialization
    
    public init(
        nodeId: String,
        bindAddress: String = "0.0.0.0",
        port: UInt16,
        messageHandler: @escaping (RunarNetworkMessage) -> Void
    ) {
        self.nodeId = nodeId
        self.bindAddress = bindAddress
        self.port = port
        self.messageHandler = messageHandler
        self.logger = Logger(subsystem: "com.runar.transporter", category: "quic")
        
        logger.info("🚀 [QuicTransporter] Initialized - Node: \(nodeId), Address: \(bindAddress):\(port)")
    }
    
    // MARK: - Public API
    
    /// Start the transporter and begin listening for connections
    public func start() async throws {
        logger.info("🔄 [QuicTransporter] Starting transporter...")
        
        await stateQueue.sync {
            guard !isRunning else {
                logger.warning("⚠️ [QuicTransporter] Already running")
                return
            }
            isRunning = true
        }
        
        #if canImport(Network)
        // Apple platforms - use Network.framework
        try await startNetworkFramework()
        #else
        // Linux - simple implementation
        await startSimpleImplementation()
        #endif
        
        logger.info("✅ [QuicTransporter] Started successfully")
    }
    
    /// Stop the transporter and clean up resources
    public func stop() async {
        logger.info("🔄 [QuicTransporter] Stopping transporter...")
        
        await stateQueue.sync {
            guard isRunning else {
                logger.warning("⚠️ [QuicTransporter] Not running")
                return
            }
            isRunning = false
        }
        
        #if canImport(Network)
        // Apple platforms
        await stopNetworkFramework()
        #else
        // Linux
        await stopSimpleImplementation()
        #endif
        
        logger.info("✅ [QuicTransporter] Stopped successfully")
    }
    
    /// Connect to a peer
    public func connect(to peerAddress: String, peerPort: UInt16, peerId: String) async throws {
        logger.info("🔗 [QuicTransporter] Connecting to \(peerId) at \(peerAddress):\(peerPort)")
        
        await stateQueue.sync {
            guard isRunning else {
                logger.error("❌ [QuicTransporter] Not running - cannot connect")
                return
            }
        }
        
        #if canImport(Network)
        try await connectNetworkFramework(to: peerAddress, peerPort: peerPort, peerId: peerId)
        #else
        try await connectSimpleImplementation(to: peerAddress, peerPort: peerPort, peerId: peerId)
        #endif
    }
    
    /// Send a message to a peer
    public func send(message: RunarNetworkMessage, to peerId: String) async throws {
        logger.info("📤 [QuicTransporter] Sending message to \(peerId) - Type: \(message.messageType)")
        
        await stateQueue.sync {
            guard isRunning else {
                logger.error("❌ [QuicTransporter] Not running - cannot send message")
                return
            }
        }
        
        #if canImport(Network)
        try await sendNetworkFramework(message: message, to: peerId)
        #else
        try await sendSimpleImplementation(message: message, to: peerId)
        #endif
    }
    
    /// Check if connected to a peer
    public func isConnected(to peerId: String) async -> Bool {
        #if canImport(Network)
        return await isConnectedNetworkFramework(to: peerId)
        #else
        return await isConnectedSimpleImplementation(to: peerId)
        #endif
    }
    
    /// Get list of connected peers
    public func getConnectedPeers() async -> [String] {
        #if canImport(Network)
        return await getConnectedPeersNetworkFramework()
        #else
        return await getConnectedPeersSimpleImplementation()
        #endif
    }
    
    // MARK: - Network.framework Implementation (Apple platforms)
    
    #if canImport(Network)
    private func startNetworkFramework() async throws {
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(bindAddress),
            port: NWEndpoint.Port(integerLiteral: port)
        )
        
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        
        listener = NWListener(using: parameters, on: endpoint)
        
        listener?.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            
            switch state {
            case .ready:
                self.logger.info("✅ [QuicTransporter] Listener ready on \(self.bindAddress):\(self.port)")
            case .failed(let error):
                self.logger.error("❌ [QuicTransporter] Listener failed: \(error)")
            case .cancelled:
                self.logger.info("🔚 [QuicTransporter] Listener cancelled")
            default:
                self.logger.debug("🔄 [QuicTransporter] Listener state: \(state)")
            }
        }
        
        listener?.newConnectionHandler = { [weak self] connection in
            guard let self = self else { return }
            self.handleNewConnection(connection)
        }
        
        listener?.start(queue: connectionQueue)
    }
    
    private func stopNetworkFramework() async {
        listener?.cancel()
        listener = nil
        
        await connectionQueue.sync {
            for (peerId, connection) in connections {
                logger.debug("🔚 [QuicTransporter] Closing connection to \(peerId)")
                connection.cancel()
            }
            connections.removeAll()
        }
    }
    
    private func connectNetworkFramework(to peerAddress: String, peerPort: UInt16, peerId: String) async throws {
        await connectionQueue.sync {
            guard connections[peerId] == nil else {
                logger.info("ℹ️ [QuicTransporter] Already connected to \(peerId)")
                return
            }
        }
        
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(peerAddress),
            port: NWEndpoint.Port(integerLiteral: peerPort)
        )
        
        let parameters = NWParameters.tcp
        let connection = NWConnection(to: endpoint, using: parameters)
        
        connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            
            switch state {
            case .ready:
                self.logger.info("✅ [QuicTransporter] Connected to \(peerId)")
                self.startReceiving(from: connection, peerId: peerId)
            case .failed(let error):
                self.logger.error("❌ [QuicTransporter] Connection to \(peerId) failed: \(error)")
                self.removeConnection(peerId: peerId)
            case .cancelled:
                self.logger.info("🔚 [QuicTransporter] Connection to \(peerId) cancelled")
                self.removeConnection(peerId: peerId)
            default:
                self.logger.debug("🔄 [QuicTransporter] Connection to \(peerId) state: \(state)")
            }
        }
        
        connection.start(queue: connectionQueue)
        
        await connectionQueue.sync {
            connections[peerId] = connection
        }
    }
    
    private func sendNetworkFramework(message: RunarNetworkMessage, to peerId: String) async throws {
        let connection = await connectionQueue.sync {
            connections[peerId]
        }
        
        guard let connection = connection else {
            throw QuicTransportError.peerNotConnected(peerId)
        }
        
        let packet = NetworkQuicPacket(
            streamType: .unidirectional,
            message: message
        )
        
        let data = try JSONEncoder().encode(packet)
        
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            if let error = error {
                self?.logger.error("❌ [QuicTransporter] Failed to send message to \(peerId): \(error)")
            } else {
                self?.logger.debug("✅ [QuicTransporter] Message sent to \(peerId)")
            }
        })
    }
    
    private func isConnectedNetworkFramework(to peerId: String) async -> Bool {
        await connectionQueue.sync {
            connections[peerId] != nil
        }
    }
    
    private func getConnectedPeersNetworkFramework() async -> [String] {
        await connectionQueue.sync {
            Array(connections.keys)
        }
    }
    
    private func handleNewConnection(_ connection: NWConnection) {
        logger.info("🆕 [QuicTransporter] New incoming connection")
        
        connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            
            switch state {
            case .ready:
                self.logger.info("✅ [QuicTransporter] Incoming connection ready")
                self.startReceiving(from: connection, peerId: "unknown")
            case .failed(let error):
                self.logger.error("❌ [QuicTransporter] Incoming connection failed: \(error)")
            case .cancelled:
                self.logger.info("🔚 [QuicTransporter] Incoming connection cancelled")
            default:
                self.logger.debug("🔄 [QuicTransporter] Incoming connection state: \(state)")
            }
        }
        
        connection.start(queue: connectionQueue)
    }
    
    private func startReceiving(from connection: NWConnection, peerId: String) {
        receiveNextMessage(from: connection, peerId: peerId)
    }
    
    private func receiveNextMessage(from connection: NWConnection, peerId: String) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, error in
            guard let self = self else { return }
            
            if let error = error {
                self.logger.error("❌ [QuicTransporter] Receive error from \(peerId): \(error)")
                return
            }
            
            if let data = content {
                self.handleReceivedData(data, from: peerId)
            }
            
            if !isComplete {
                self.receiveNextMessage(from: connection, peerId: peerId)
            }
        }
    }
    
    private func removeConnection(peerId: String) {
        connectionQueue.async {
            self.connections.removeValue(forKey: peerId)
            self.logger.info("🔚 [QuicTransporter] Removed connection to \(peerId)")
        }
    }
    #endif
    
    // MARK: - Simple Implementation (Linux)
    
    #if !canImport(Network)
    private func startSimpleImplementation() async {
        await stateQueue.sync {
            isListening = true
        }
        logger.info("✅ [QuicTransporter] Simple implementation started (Linux)")
    }
    
    private func stopSimpleImplementation() async {
        await stateQueue.sync {
            isListening = false
            connectedPeers.removeAll()
        }
    }
    
    private func connectSimpleImplementation(to peerAddress: String, peerPort: UInt16, peerId: String) async throws {
        await stateQueue.sync {
            connectedPeers.insert(peerId)
        }
        logger.info("✅ [QuicTransporter] Simple connection to \(peerId) established")
    }
    
    private func sendSimpleImplementation(message: RunarNetworkMessage, to peerId: String) async throws {
        await stateQueue.sync {
            guard connectedPeers.contains(peerId) else {
                logger.error("❌ [QuicTransporter] Not connected to \(peerId)")
                return
            }
        }
        
        // Simulate message processing
        messageQueue.async {
            self.messageHandler(message)
        }
        
        logger.debug("✅ [QuicTransporter] Message sent to \(peerId) (simulated)")
    }
    
    private func isConnectedSimpleImplementation(to peerId: String) async -> Bool {
        await stateQueue.sync {
            connectedPeers.contains(peerId)
        }
    }
    
    private func getConnectedPeersSimpleImplementation() async -> [String] {
        await stateQueue.sync {
            Array(connectedPeers)
        }
    }
    #endif
    
    // MARK: - Shared Methods
    
    private func handleReceivedData(_ data: Data, from peerId: String) {
        logger.debug("📥 [QuicTransporter] Received \(data.count) bytes from \(peerId)")
        
        do {
            let packet = try JSONDecoder().decode(NetworkQuicPacket.self, from: data)
            logger.info("📥 [QuicTransporter] Received message from \(peerId) - Type: \(packet.message.messageType)")
            
            messageQueue.async {
                self.messageHandler(packet.message)
            }
        } catch {
            logger.error("❌ [QuicTransporter] Failed to decode message from \(peerId): \(error)")
        }
    }
}

// MARK: - Supporting Types

/// Network packet wrapper for QUIC-like transport
public struct NetworkQuicPacket: Codable {
    public let streamType: StreamType
    public let message: RunarNetworkMessage
    
    public init(streamType: StreamType, message: RunarNetworkMessage) {
        self.streamType = streamType
        self.message = message
    }
}

/// Stream types for QUIC-like transport
public enum StreamType: String, Codable {
    case unidirectional = "uni"
    case bidirectional = "bi"
}

/// Transport-specific errors
public enum QuicTransportError: Error, LocalizedError {
    case peerNotConnected(String)
    case transportNotRunning
    case encodingError(String)
    case decodingError(String)
    
    public var errorDescription: String? {
        switch self {
        case .peerNotConnected(let peerId):
            return "Peer \(peerId) is not connected"
        case .transportNotRunning:
            return "Transport is not running"
        case .encodingError(let message):
            return "Encoding error: \(message)"
        case .decodingError(let message):
            return "Decoding error: \(message)"
        }
    }
} 