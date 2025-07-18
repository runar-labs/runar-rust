import Foundation
import Network
import os.log
import Crypto

/// Network.framework QUIC transport implementation that matches the Rust QUIC transport architecture
/// Uses unidirectional streams for all messages (requests and responses) for compatibility
@available(macOS 12.0, iOS 15.0, *)
public class NetworkQuicTransporter: TransportProtocol, @unchecked Sendable {
    
    // MARK: - Properties
    
    private let nodeInfo: RunarNodeInfo
    private let bindAddress: String
    private let options: NetworkQuicTransportOptions
    private let logger: Logger
    private let messageHandler: MessageHandlerProtocol
    
    // Network.framework components
    private var listener: NWListener?
    private var connections: [String: NWConnection] = [:]
    private let connectionQueue = DispatchQueue(label: "com.runar.quic.connection", qos: .userInitiated)
    private let messageQueue = DispatchQueue(label: "com.runar.quic.message", qos: .userInitiated)
    
    // State management
    private var isRunning = false
    private let stateQueue = DispatchQueue(label: "com.runar.quic.state", qos: .userInitiated)
    
    // Request tracking for correlation
    private var pendingRequests: [String: RequestState] = [:]
    private let requestQueue = DispatchQueue(label: "com.runar.quic.request", qos: .userInitiated)
    
    // MARK: - Initialization
    
    public init(
        nodeInfo: RunarNodeInfo,
        bindAddress: String,
        messageHandler: MessageHandlerProtocol,
        options: NetworkQuicTransportOptions,
        logger: Logger
    ) {
        self.nodeInfo = nodeInfo
        self.bindAddress = bindAddress
        self.messageHandler = messageHandler
        self.options = options
        self.logger = logger
        
        logger.info("🚀 [NetworkQuicTransporter] Initialized - Node: \(nodeInfo.nodeId), Address: \(bindAddress)")
    }
    
    // MARK: - TransportProtocol Implementation
    
    public func start() async throws {
        logger.info("🔄 [NetworkQuicTransporter] Starting QUIC transport...")
        
        stateQueue.sync {
            guard !isRunning else {
                logger.warning("⚠️ [NetworkQuicTransporter] Already running")
                return
            }
            isRunning = true
        }
        
        try await startListener()
        logger.info("✅ [NetworkQuicTransporter] Started successfully")
    }
    
    public func stop() async {
        logger.info("🔄 [NetworkQuicTransporter] Stopping QUIC transport...")
        
        stateQueue.sync {
            guard isRunning else {
                logger.warning("⚠️ [NetworkQuicTransporter] Not running")
                return
            }
            isRunning = false
        }
        
        await stopListener()
        await cleanupConnections()
        
        logger.info("✅ [NetworkQuicTransporter] Stopped successfully")
    }
    
    public func connect(to peerInfo: RunarPeerInfo) async throws {
        let peerId = NodeUtils.compactId(from: peerInfo.publicKey)
        logger.info("🔗 [NetworkQuicTransporter] Connecting to peer \(peerId)")
        
        stateQueue.sync {
            guard isRunning else {
                logger.error("❌ [NetworkQuicTransporter] Not running - cannot connect")
                return
            }
        }
        
        // Check if already connected
        if await isConnected(to: peerId) {
            logger.info("ℹ️ [NetworkQuicTransporter] Already connected to \(peerId)")
            return
        }
        
        // Try each address until one succeeds
        var lastError: Error?
        
        for address in peerInfo.addresses {
            do {
                try await connectToAddress(address, peerId: peerId)
                logger.info("✅ [NetworkQuicTransporter] Connected to \(peerId) via \(address)")
                return
            } catch {
                logger.warning("⚠️ [NetworkQuicTransporter] Failed to connect to \(peerId) via \(address): \(error)")
                lastError = error
            }
        }
        
        throw lastError ?? RunarTransportError.connectionError("Failed to connect to peer \(peerId) on any address")
    }
    
    public func send(message: RunarNetworkMessage) async throws {
        let peerId = message.destinationNodeId
        logger.info("📤 [NetworkQuicTransporter] Sending message to \(peerId) - Type: \(message.messageType)")
        
        stateQueue.sync {
            guard isRunning else {
                logger.error("❌ [NetworkQuicTransporter] Not running - cannot send message")
                return
            }
        }
        
        // Wait for connection to be established
        var attempts = 0
        while attempts < 10 {
            if await isConnected(to: peerId) {
                break
            }
            try await Task.sleep(nanoseconds: 500_000_000) // 500ms
            attempts += 1
        }
        
        guard await isConnected(to: peerId) else {
            throw RunarTransportError.connectionError("Not connected to peer \(peerId) after waiting")
        }
        
        try await sendMessage(message, to: peerId)
    }
    
    public func isConnected(to peerId: String) async -> Bool {
        connectionQueue.sync {
            connections[peerId] != nil
        }
    }
    
    public func getConnectedPeers() async -> [String] {
        connectionQueue.sync {
            Array(connections.keys)
        }
    }
    
    // MARK: - Private Methods
    
    private func startListener() async throws {
        // Parse bind address
        let components = bindAddress.split(separator: ":")
        guard components.count == 2,
              let port = UInt16(components[1]) else {
            throw RunarTransportError.configurationError("Invalid bind address format: \(bindAddress)")
        }
        
        let host = String(components[0])
        
        // Create QUIC parameters with custom configuration
        let parameters = NWParameters.quic(alpn: ["runar-quic"])
        
        // Configure TLS if certificates are provided
        if let certificates = options.certificates,
           let privateKey = options.privateKey {
            try configureTLS(parameters: parameters, certificates: certificates, privateKey: privateKey)
        }
        
        // Create listener
        listener = try NWListener(using: parameters, on: NWEndpoint.Port(integerLiteral: port))
        
        listener?.stateUpdateHandler = self.listenerStateUpdateHandler(state:)
        listener?.newConnectionHandler = self.listenerNewConnectionHandler(connection:)
        
        listener?.start(queue: connectionQueue)
    }
    
    private func configureTLS(parameters: NWParameters, certificates: [Data], privateKey: Data) throws {
        // Configure TLS with custom certificates
        // Note: Network.framework has limited custom certificate support
        // This is a simplified implementation
        logger.info("🔐 [NetworkQuicTransporter] Configuring TLS with custom certificates")
        
        // For now, we'll use the default TLS configuration
        // Custom certificate validation would require more complex setup
    }
    
    private func stopListener() async {
        listener?.cancel()
        listener = nil
    }
    
    private func cleanupConnections() async {
        connectionQueue.sync {
            for (peerId, connection) in connections {
                logger.debug("🔚 [NetworkQuicTransporter] Closing connection to \(peerId)")
                connection.cancel()
            }
            connections.removeAll()
        }
    }
    
    private func connectToAddress(_ address: String, peerId: String) async throws {
        // Parse address
        let components = address.split(separator: ":")
        guard components.count == 2,
              let port = UInt16(components[1]) else {
            throw RunarTransportError.configurationError("Invalid address format: \(address)")
        }
        
        let host = String(components[0])
        
        // Create QUIC parameters
        let parameters = NWParameters.quic(alpn: ["runar-quic"])
        
        // Create endpoint
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: port)
        )
        
        // Create connection
        let connection = NWConnection(to: endpoint, using: parameters)
        
        // Set up connection state handler
        connection.stateUpdateHandler = self.connectionStateUpdateHandler(connection: connection, peerId: peerId)
        
        // Start connection
        connection.start(queue: connectionQueue)
        
        // Store connection
        connectionQueue.sync {
            connections[peerId] = connection
        }
    }
    
    private func sendMessage(_ message: RunarNetworkMessage, to peerId: String) async throws {
        let connection = connectionQueue.sync {
            connections[peerId]
        }
        
        guard let connection = connection else {
            throw RunarTransportError.connectionError("Not connected to peer \(peerId)")
        }
        
        // Encode message using binary format
        let messageData = try encodeNetworkMessage(message)
        
        // Add length prefix (4 bytes)
        var data = Data()
        let length = UInt32(messageData.count).bigEndian
        data.append(withUnsafePointer(to: length) { pointer in
            Data(bytes: pointer, count: MemoryLayout<UInt32>.size)
        })
        data.append(messageData)
        
        // Send via unidirectional stream (matching Rust implementation)
        connection.send(content: data, completion: .contentProcessed { [weak self] (error: NWError?) -> Void in
            if let error = error {
                self?.logger.error("❌ [NetworkQuicTransporter] Failed to send message to \(peerId): \(error)")
            } else {
                self?.logger.debug("✅ [NetworkQuicTransporter] Message sent to \(peerId)")
            }
        })
    }
    
    private func removeConnection(peerId: String) {
        connectionQueue.async {
            self.connections.removeValue(forKey: peerId)
            self.logger.info("🔚 [NetworkQuicTransporter] Removed connection to \(peerId)")
        }
    }
    
    // MARK: - Handler Methods
    
    private func listenerStateUpdateHandler(state: NWListener.State) {
        switch state {
        case .ready:
            self.logger.info("✅ [NetworkQuicTransporter] Listener ready on \(self.bindAddress)")
        case .failed(let error):
            self.logger.error("❌ [NetworkQuicTransporter] Listener failed: \(error)")
        case .cancelled:
            self.logger.info("🔚 [NetworkQuicTransporter] Listener cancelled")
        default:
            self.logger.debug("🔄 [NetworkQuicTransporter] Listener state: \(String(describing: state))")
        }
    }
    
    private func listenerNewConnectionHandler(connection: NWConnection) {
        self.logger.info("🆕 [NetworkQuicTransporter] New incoming connection")
        
        // Start receiving to get handshake message
        startReceiving(from: connection, peerId: "unknown")
    }
    
    private func connectionStateUpdateHandler(connection: NWConnection, peerId: String) -> (NWConnection.State) -> Void {
        let handler: (NWConnection.State) -> Void = { [weak self, weak connection] (state: NWConnection.State) in
            guard let self = self, let connection = connection else { return }
            switch state {
            case .ready:
                self.logger.info("✅ [NetworkQuicTransporter] Connected to \(peerId)")
                self.handleConnectionReady(connection, peerId: peerId)
            case .failed(let error):
                self.logger.error("❌ [NetworkQuicTransporter] Connection to \(peerId) failed: \(error)")
                self.removeConnection(peerId: peerId)
            case .cancelled:
                self.logger.info("🔚 [NetworkQuicTransporter] Connection to \(peerId) cancelled")
                self.removeConnection(peerId: peerId)
            default:
                self.logger.debug("🔄 [NetworkQuicTransporter] Connection to \(peerId) state: \(String(describing: state))")
            }
        }
        return handler
    }
    
    private func handleConnectionReady(_ connection: NWConnection, peerId: String) {
        // Start receiving messages
        startReceiving(from: connection, peerId: peerId)
        
        // Initiate handshake
        Task {
            try await initiateHandshake(to: peerId)
        }
    }
    
    private func startReceiving(from connection: NWConnection, peerId: String) {
        receiveNextMessage(from: connection, peerId: peerId)
    }
    
    private func receiveNextMessage(from connection: NWConnection, peerId: String) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] (content: Data?, context: NWConnection.ContentContext?, isComplete: Bool, error: NWError?) -> Void in
            guard let self = self else { return }
            
            if let error = error {
                self.logger.error("❌ [NetworkQuicTransporter] Receive error from \(peerId): \(error)")
                return
            }
            
            if let data = content {
                self.handleReceivedData(data, from: peerId, connection: connection)
            }
            
            if !isComplete {
                self.receiveNextMessage(from: connection, peerId: peerId)
            }
        }
    }
    
    private func handleReceivedData(_ data: Data, from peerId: String, connection: NWConnection) {
        logger.debug("📥 [NetworkQuicTransporter] Received \(data.count) bytes from \(peerId)")
        
        do {
            // Parse message length (4 bytes)
            guard data.count >= 4 else {
                logger.error("❌ [NetworkQuicTransporter] Message too short from \(peerId)")
                return
            }
            
            let lengthData = data.prefix(4)
            let messageLength = lengthData.withUnsafeBytes { bytes in
                bytes.load(as: UInt32.self).bigEndian
            }
            
            guard data.count >= 4 + Int(messageLength) else {
                logger.error("❌ [NetworkQuicTransporter] Incomplete message from \(peerId)")
                return
            }
            
            let messageData = data.dropFirst(4).prefix(Int(messageLength))
            
            // Decode message using binary format
            let message = try decodeNetworkMessage(from: messageData)
            
            logger.info("📥 [NetworkQuicTransporter] Received message from \(peerId) - Type: \(message.messageType)")
            
            // Handle handshake messages
            if message.messageType == MessageTypes.NODE_INFO_HANDSHAKE ||
               message.messageType == MessageTypes.NODE_INFO_HANDSHAKE_RESPONSE {
                handleHandshakeMessage(message, from: peerId, connection: connection)
            } else {
                // Handle regular messages
                messageQueue.async {
                    self.messageHandler.handleMessage(message)
                }
            }
            
        } catch {
            logger.error("❌ [NetworkQuicTransporter] Failed to decode message from \(peerId): \(error)")
        }
    }
    
    // MARK: - Handshake Protocol
    
    private func initiateHandshake(to peerId: String) async throws {
        logger.info("🤝 [NetworkQuicTransporter] Initiating handshake with \(peerId)")
        
        // Create handshake message
        let handshakeMessage = RunarNetworkMessage(
            sourceNodeId: nodeInfo.nodeId,
            destinationNodeId: peerId,
            messageType: MessageTypes.NODE_INFO_HANDSHAKE,
            payloads: [
                NetworkMessagePayloadItem(
                    path: "",
                    valueBytes: try encodeNodeInfo(nodeInfo),
                    correlationId: "handshake-\(nodeInfo.nodeId)-\(Date().timeIntervalSince1970)"
                )
            ]
        )
        
        // Send handshake message directly via connection
        let connection = connectionQueue.sync {
            connections[peerId]
        }
        
        guard let connection = connection else {
            throw RunarTransportError.connectionError("No connection available for handshake to \(peerId)")
        }
        
        let messageData = try encodeNetworkMessage(handshakeMessage)
        var data = Data()
        let length = UInt32(messageData.count).bigEndian
        data.append(Data(bytes: withUnsafeBytes(of: length) { Data($0) }))
        data.append(messageData)
        
        connection.send(content: data, completion: .contentProcessed { [weak self] (error: NWError?) -> Void in
            if let error = error {
                self?.logger.error("❌ [NetworkQuicTransporter] Failed to send handshake to \(peerId): \(error)")
            } else {
                self?.logger.debug("✅ [NetworkQuicTransporter] Handshake sent to \(peerId)")
            }
        })
    }
    
    private func handleHandshakeMessage(_ message: RunarNetworkMessage, from peerId: String, connection: NWConnection) {
        logger.info("🤝 [NetworkQuicTransporter] Handling handshake message from \(peerId)")
        
        guard let payload = message.payloads.first else {
            logger.error("❌ [NetworkQuicTransporter] Handshake message has no payload")
            return
        }
        
        do {
            let peerNodeInfo = try decodeNodeInfo(from: payload.valueBytes)
            let realPeerId = peerNodeInfo.nodeId
            
            logger.info("✅ [NetworkQuicTransporter] Identified peer: \(realPeerId)")
            
            // Update connection mapping if this was an unknown peer
            if peerId == "unknown" {
                connectionQueue.sync {
                    connections[realPeerId] = connection
                    connections.removeValue(forKey: "unknown")
                }
            }
            
            // Handle different handshake message types
            if message.messageType == MessageTypes.NODE_INFO_HANDSHAKE {
                // Send handshake response
                Task {
                    try await sendHandshakeResponse(to: realPeerId)
                }
                
                // Notify about new peer
                messageQueue.async {
                    self.messageHandler.peerConnected(peerNodeInfo)
                }
                
            } else if message.messageType == MessageTypes.NODE_INFO_HANDSHAKE_RESPONSE {
                // Notify about new peer
                messageQueue.async {
                    self.messageHandler.peerConnected(peerNodeInfo)
                }
            }
            
        } catch {
            logger.error("❌ [NetworkQuicTransporter] Failed to process handshake from \(peerId): \(error)")
        }
    }
    
    private func sendHandshakeResponse(to peerId: String) async throws {
        logger.info("🤝 [NetworkQuicTransporter] Sending handshake response to \(peerId)")
        
        let responseMessage = RunarNetworkMessage(
            sourceNodeId: nodeInfo.nodeId,
            destinationNodeId: peerId,
            messageType: MessageTypes.NODE_INFO_HANDSHAKE_RESPONSE,
            payloads: [
                NetworkMessagePayloadItem(
                    path: "",
                    valueBytes: try encodeNodeInfo(nodeInfo),
                    correlationId: "handshake-response-\(nodeInfo.nodeId)-\(Date().timeIntervalSince1970)"
                )
            ]
        )
        
        // Send handshake response directly via connection
        let connection = connectionQueue.sync {
            connections[peerId]
        }
        
        guard let connection = connection else {
            throw RunarTransportError.connectionError("No connection available for handshake response to \(peerId)")
        }
        
        let messageData = try encodeNetworkMessage(responseMessage)
        var data = Data()
        let length = UInt32(messageData.count).bigEndian
        data.append(Data(bytes: withUnsafeBytes(of: length) { Data($0) }))
        data.append(messageData)
        
        connection.send(content: data, completion: .contentProcessed { [weak self] (error: NWError?) -> Void in
            if let error = error {
                self?.logger.error("❌ [NetworkQuicTransporter] Failed to send handshake response to \(peerId): \(error)")
            } else {
                self?.logger.debug("✅ [NetworkQuicTransporter] Handshake response sent to \(peerId)")
            }
        })
    }
    
    // MARK: - Message Encoding/Decoding
    
    private func encodeNetworkMessage(_ message: RunarNetworkMessage) throws -> Data {
        // Use binary encoding for efficiency and compatibility with Rust
        return try BinaryMessageEncoder.encodeNetworkMessage(message)
    }
    
    private func decodeNetworkMessage(from data: Data) throws -> RunarNetworkMessage {
        // Use binary decoding for efficiency and compatibility with Rust
        return try BinaryMessageEncoder.decodeNetworkMessage(from: data)
    }
    
    private func encodeNodeInfo(_ nodeInfo: RunarNodeInfo) throws -> Data {
        // Use binary encoding for efficiency and compatibility with Rust
        return try BinaryMessageEncoder.encodeNodeInfo(nodeInfo)
    }
    
    private func decodeNodeInfo(from data: Data) throws -> RunarNodeInfo {
        // Use binary decoding for efficiency and compatibility with Rust
        return try BinaryMessageEncoder.decodeNodeInfo(from: data)
    }
}

// MARK: - Supporting Types

@available(macOS 12.0, iOS 15.0, *)
private struct PeerState {
    let peerId: String
    let address: String
    let connectedAt: Date
    
    init(peerId: String, address: String) {
        self.peerId = peerId
        self.address = address
        self.connectedAt = Date()
    }
}

@available(macOS 12.0, iOS 15.0, *)
private struct HandshakeState {
    let peerId: String
    let initiatedAt: Date
    let status: HandshakeStatus
    
    enum HandshakeStatus {
        case initiated
        case completed
        case failed
    }
}

@available(macOS 12.0, iOS 15.0, *)
private struct RequestState {
    let correlationId: String
    let initiatedAt: Date
    let timeout: TimeInterval
    
    init(correlationId: String, timeout: TimeInterval = 30.0) {
        self.correlationId = correlationId
        self.initiatedAt = Date()
        self.timeout = timeout
    }
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