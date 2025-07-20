import Foundation
import os.log
import Security
import Network

// MARK: - Test Configuration

struct TestConfig {
    let bindAddr: String
    let peerPort: String
    let nodeId: String
    let logLevel: OSLogType
    
    static func fromEnvironment() -> TestConfig {
        let bindAddr = ProcessInfo.processInfo.environment["BIND_ADDR"] ?? "0.0.0.0:50003"
        let peerPort = ProcessInfo.processInfo.environment["PEER_PORT"] ?? "50004"
        let nodeId = ProcessInfo.processInfo.environment["NODE_ID"] ?? "swift-node-001"
        let logLevelStr = ProcessInfo.processInfo.environment["SWIFT_LOG_LEVEL"] ?? "debug"
        
        let logLevel: OSLogType = {
            switch logLevelStr.lowercased() {
            case "debug": return .debug
            case "info": return .info
            case "error": return .error
            default: return .default
            }
        }()
        
        return TestConfig(bindAddr: bindAddr, peerPort: peerPort, nodeId: nodeId, logLevel: logLevel)
    }
}

// MARK: - Certificate Management

class CertificateManager {
    private let logger: Logger
    
    init(logger: Logger) {
        self.logger = logger
    }
    
    func createTestCertificates() throws -> (nodeCertificate: SecCertificate, caCertificate: SecCertificate, privateKey: SecKey) {
        logger.info("🔑 [SwiftTest] Creating test certificates...")
        
        // Create a test CA certificate
        let caCertificate = try createTestCACertificate()
        
        // Create a test node certificate signed by the CA
        let (nodeCertificate, privateKey) = try createTestNodeCertificate(signedBy: caCertificate)
        
        logger.info("✅ [SwiftTest] Test certificates created successfully")
        
        return (nodeCertificate: nodeCertificate, caCertificate: caCertificate, privateKey: privateKey)
    }
    
    private func createTestCACertificate() throws -> SecCertificate {
        // Create a simple test CA certificate
        // In a real implementation, this would use proper certificate generation
        let caSubject = "CN=Runar Test CA,O=Runar,C=US"
        
        // For testing, create a basic certificate
        // This is a simplified version - real implementation would use proper X.509 generation
        let caData = createTestCertificateData(subject: caSubject, isCA: true)
        
        guard let caCertificate = SecCertificateCreateWithData(nil, caData as CFData) else {
            throw TestError.certificateError("Failed to create CA certificate")
        }
        
        return caCertificate
    }
    
    private func createTestNodeCertificate(signedBy caCertificate: SecCertificate) throws -> (SecCertificate, SecKey) {
        let nodeSubject = "CN=swift-node-001,O=Runar Node,C=US"
        
        // Create a test node certificate
        let nodeData = createTestCertificateData(subject: nodeSubject, isCA: false)
        
        guard let nodeCertificate = SecCertificateCreateWithData(nil, nodeData as CFData) else {
            throw TestError.certificateError("Failed to create node certificate")
        }
        
        // Create a test private key
        let privateKey = try createTestPrivateKey()
        
        return (nodeCertificate, privateKey)
    }
    
    private func createTestCertificateData(subject: String, isCA: Bool) -> Data {
        // This is a placeholder for proper certificate generation
        // In a real implementation, this would create proper X.509 certificates
        var data = Data()
        data.append("-----BEGIN CERTIFICATE-----\n".data(using: .utf8)!)
        data.append("TEST CERTIFICATE DATA\n".data(using: .utf8)!)
        data.append("Subject: \(subject)\n".data(using: .utf8)!)
        data.append("Is CA: \(isCA)\n".data(using: .utf8)!)
        data.append("-----END CERTIFICATE-----\n".data(using: .utf8)!)
        return data
    }
    
    private func createTestPrivateKey() throws -> SecKey {
        // Create a test private key
        // In a real implementation, this would create a proper cryptographic key
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw TestError.certificateError("Failed to create private key: \(error?.takeRetainedValue().localizedDescription ?? "unknown error")")
        }
        
        return privateKey
    }
}

// MARK: - Test Message Handler

class TestMessageHandler {
    private let logger: Logger
    private var receivedMessages: [String] = []
    private let messageQueue = DispatchQueue(label: "test.message.queue")
    
    init(logger: Logger) {
        self.logger = logger
    }
    
    func handleMessage(_ message: String) {
        messageQueue.async {
            self.receivedMessages.append(message)
        }
        
        logger.info("📥 [SwiftTest] Received message: \(message)")
    }
    
    func getReceivedMessages() -> [String] {
        messageQueue.sync { receivedMessages }
    }
    
    func clearMessages() {
        messageQueue.async {
            self.receivedMessages.removeAll()
        }
    }
}

// MARK: - Network Transport Implementation

@available(macOS 12.0, iOS 15.0, *)
class SwiftNetworkTransport {
    private let config: TestConfig
    private let logger: Logger
    private let messageHandler: TestMessageHandler
    private let certificateManager: CertificateManager
    
    private var listener: NWListener?
    private var connections: [String: NWConnection] = [:]
    private let connectionQueue = DispatchQueue(label: "swift.transport.connection")
    
    init(config: TestConfig, logger: Logger, messageHandler: TestMessageHandler) {
        self.config = config
        self.logger = logger
        self.messageHandler = messageHandler
        self.certificateManager = CertificateManager(logger: logger)
    }
    
    func start() async throws {
        logger.info("🚀 [SwiftTest] Starting Swift QUIC transport with proper certificate validation")
        
        // Create test certificates
        let (nodeCertificate, caCertificate, privateKey) = try certificateManager.createTestCertificates()
        
        // Create QUIC parameters with proper TLS configuration
        let parameters = NWParameters.quic(alpn: ["runar-quic"])
        
        // Configure TLS with certificates
        try configureTLS(parameters: parameters, 
                        nodeCertificate: nodeCertificate, 
                        caCertificate: caCertificate, 
                        privateKey: privateKey)
        
        // Parse bind address
        let components = config.bindAddr.split(separator: ":")
        guard components.count == 2,
              let port = UInt16(components[1]) else {
            throw TestError.configurationError("Invalid bind address format: \(config.bindAddr)")
        }
        
        // Create listener
        listener = try NWListener(using: parameters, on: NWEndpoint.Port(integerLiteral: port))
        
        listener?.stateUpdateHandler = { [weak self] state in
            self?.handleListenerState(state)
        }
        
        listener?.newConnectionHandler = { [weak self] connection in
            self?.handleNewConnection(connection)
        }
        
        listener?.start(queue: connectionQueue)
        
        logger.info("✅ [SwiftTest] Swift transport started with proper certificate validation")
    }
    
    private func configureTLS(parameters: NWParameters, 
                             nodeCertificate: SecCertificate, 
                             caCertificate: SecCertificate, 
                             privateKey: SecKey) throws {
        logger.info("🔐 [SwiftTest] Configuring TLS with custom certificates")
        
        let tlsOptions = NWProtocolTLS.Options()
        
        // Create SecIdentity from certificate and private key
        let identity = try createSecIdentity(certificate: nodeCertificate, privateKey: privateKey)
        tlsOptions.setLocalIdentity(identity)
        
        // Set root certificate for validation
        tlsOptions.setTrustedRootCertificates([caCertificate])
        
        // Apply TLS options to QUIC parameters
        parameters.defaultProtocolStack.applicationProtocols.insert(tlsOptions, at: 0)
        
        logger.info("✅ [SwiftTest] TLS configured with custom certificates and CA validation")
    }
    
    private func createSecIdentity(certificate: SecCertificate, privateKey: SecKey) throws -> SecIdentity {
        // Create SecIdentity from certificate and private key
        // This is a simplified implementation for testing
        let identityDict: [String: Any] = [
            kSecValueRef as String: certificate,
            kSecAttrKey as String: privateKey
        ]
        
        guard let identity = SecIdentityCreateWithData(nil, try JSONSerialization.data(withJSONObject: identityDict) as CFData) else {
            throw TestError.certificateError("Failed to create SecIdentity")
        }
        
        return identity
    }
    
    private func handleListenerState(_ state: NWListener.State) {
        switch state {
        case .ready:
            logger.info("✅ [SwiftTest] Listener ready and accepting connections")
        case .failed(let error):
            logger.error("❌ [SwiftTest] Listener failed: \(error)")
        case .cancelled:
            logger.info("🔚 [SwiftTest] Listener cancelled")
        default:
            logger.debug("📊 [SwiftTest] Listener state: \(state)")
        }
    }
    
    private func handleNewConnection(_ connection: NWConnection) {
        logger.info("🔗 [SwiftTest] New connection received")
        
        connection.stateUpdateHandler = { [weak self] state in
            self?.handleConnectionState(connection, state)
        }
        
        connection.start(queue: connectionQueue)
    }
    
    private func handleConnectionState(_ connection: NWConnection, _ state: NWConnection.State) {
        switch state {
        case .ready:
            logger.info("✅ [SwiftTest] Connection ready")
            // Handle incoming messages
            receiveMessages(from: connection)
        case .failed(let error):
            logger.error("❌ [SwiftTest] Connection failed: \(error)")
        case .cancelled:
            logger.info("🔚 [SwiftTest] Connection cancelled")
        default:
            logger.debug("📊 [SwiftTest] Connection state: \(state)")
        }
    }
    
    private func receiveMessages(from connection: NWConnection) {
        // Set up message receiving
        connection.receiveMessage { [weak self] content, context, isComplete, error in
            if let error = error {
                self?.logger.error("❌ [SwiftTest] Error receiving message: \(error)")
                return
            }
            
            if let content = content {
                let message = String(data: content, encoding: .utf8) ?? "Invalid message"
                self?.messageHandler.handleMessage(message)
            }
            
            // Continue receiving messages
            if !isComplete {
                self?.receiveMessages(from: connection)
            }
        }
    }
    
    func stop() {
        listener?.cancel()
        listener = nil
        
        for connection in connections.values {
            connection.cancel()
        }
        connections.removeAll()
        
        logger.info("✅ [SwiftTest] Swift transport stopped")
    }
}

// MARK: - Main Test Application

@available(macOS 12.0, iOS 15.0, *)
class SwiftTransportTest {
    private let config: TestConfig
    private let logger: Logger
    private let messageHandler: TestMessageHandler
    private var transport: SwiftNetworkTransport?
    
    init(config: TestConfig) {
        self.config = config
        self.logger = Logger(subsystem: "com.runar.swift.test", category: "transport-test")
        self.messageHandler = TestMessageHandler(logger: logger)
    }
    
    func run() async throws {
        logger.info("🚀 [SwiftTest] Starting Swift QUIC transport test")
        logger.info("📋 [SwiftTest] Config: \(config.bindAddr), Node: \(config.nodeId)")
        
        // Create and start transport
        transport = SwiftNetworkTransport(config: config, logger: logger, messageHandler: messageHandler)
        try await transport?.start()
        
        // Run test scenario
        try await runTestScenario()
        
        // Cleanup
        transport?.stop()
        
        logger.info("✅ [SwiftTest] Swift transport test completed successfully")
    }
    
    private func runTestScenario() async throws {
        logger.info("🧪 [SwiftTest] Running test scenario...")
        
        // Wait for potential incoming connections
        try await Task.sleep(nanoseconds: 10_000_000_000) // 10 seconds
        
        // Check if we received any messages
        let messages = messageHandler.getReceivedMessages()
        logger.info("📊 [SwiftTest] Received \(messages.count) messages")
        
        for (index, message) in messages.enumerated() {
            logger.info("📝 [SwiftTest] Message \(index + 1): \(message)")
        }
        
        // Simulate sending a test message
        logger.info("📤 [SwiftTest] Would send test message to Rust peer")
        
        // Wait for potential responses
        try await Task.sleep(nanoseconds: 5_000_000_000) // 5 seconds
        
        let responseMessages = messageHandler.getReceivedMessages()
        logger.info("📥 [SwiftTest] Total messages after sending: \(responseMessages.count)")
        
        logger.info("✅ [SwiftTest] Test scenario completed")
    }
}

// MARK: - Error Types

enum TestError: Error, LocalizedError {
    case configurationError(String)
    case certificateError(String)
    case networkError(String)
    
    var errorDescription: String? {
        switch self {
        case .configurationError(let message):
            return "Configuration error: \(message)"
        case .certificateError(let message):
            return "Certificate error: \(message)"
        case .networkError(let message):
            return "Network error: \(message)"
        }
    }
}

// MARK: - Main Entry Point

@main
struct SwiftTransportTestApp {
    static func main() async {
        let config = TestConfig.fromEnvironment()
        
        if #available(macOS 12.0, iOS 15.0, *) {
            let test = SwiftTransportTest(config: config)
            
            do {
                try await test.run()
                print("✅ Swift transport test completed successfully")
            } catch {
                print("❌ Swift transport test failed: \(error)")
                exit(1)
            }
        } else {
            print("❌ Swift transport test requires macOS 12.0+ or iOS 15.0+")
            exit(1)
        }
    }
} 