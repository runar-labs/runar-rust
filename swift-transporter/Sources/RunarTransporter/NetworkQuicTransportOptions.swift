import Foundation
import os.log

/// Configuration options for Network.framework QUIC transport
/// Matches the Rust QuicTransportOptions structure
@available(macOS 12.0, iOS 15.0, *)
public struct NetworkQuicTransportOptions {
    /// Whether to verify certificates (default: true)
    public let verifyCertificates: Bool
    
    /// Keep-alive interval for connections (default: 15 seconds)
    public let keepAliveInterval: TimeInterval
    
    /// Connection idle timeout (default: 60 seconds)
    public let connectionIdleTimeout: TimeInterval
    
    /// Stream idle timeout (default: 30 seconds)
    public let streamIdleTimeout: TimeInterval
    
    /// Maximum number of idle streams per peer (default: 100)
    public let maxIdleStreamsPerPeer: Int
    
    /// TLS certificates for secure connections
    public let certificates: [Data]?
    
    /// Private key corresponding to the certificates
    public let privateKey: Data?
    
    /// Root certificates for CA validation
    public let rootCertificates: [Data]?
    
    /// Log level for transport-related logs
    public let logLevel: OSLogType
    
    public init(
        verifyCertificates: Bool = true,
        keepAliveInterval: TimeInterval = 15.0,
        connectionIdleTimeout: TimeInterval = 60.0,
        streamIdleTimeout: TimeInterval = 30.0,
        maxIdleStreamsPerPeer: Int = 100,
        certificates: [Data]? = nil,
        privateKey: Data? = nil,
        rootCertificates: [Data]? = nil,
        logLevel: OSLogType = .default
    ) {
        self.verifyCertificates = verifyCertificates
        self.keepAliveInterval = keepAliveInterval
        self.connectionIdleTimeout = connectionIdleTimeout
        self.streamIdleTimeout = streamIdleTimeout
        self.maxIdleStreamsPerPeer = maxIdleStreamsPerPeer
        self.certificates = certificates
        self.privateKey = privateKey
        self.rootCertificates = rootCertificates
        self.logLevel = logLevel
    }
    
    /// Create default options for development/testing
    public static func `default`() -> NetworkQuicTransportOptions {
        return NetworkQuicTransportOptions()
    }
    
    /// Create options with custom certificates
    public static func withCertificates(
        certificates: [Data],
        privateKey: Data,
        verifyCertificates: Bool = true
    ) -> NetworkQuicTransportOptions {
        return NetworkQuicTransportOptions(
            verifyCertificates: verifyCertificates,
            certificates: certificates,
            privateKey: privateKey
        )
    }
    
    /// Create options optimized for mobile devices
    public static func mobileOptimized() -> NetworkQuicTransportOptions {
        return NetworkQuicTransportOptions(
            keepAliveInterval: 30.0,  // Longer keep-alive for mobile
            connectionIdleTimeout: 120.0,  // Longer idle timeout for mobile
            streamIdleTimeout: 60.0,  // Longer stream timeout for mobile
            maxIdleStreamsPerPeer: 50  // Fewer streams for mobile
        )
    }
    
    /// Create options optimized for high-performance scenarios
    public static func highPerformance() -> NetworkQuicTransportOptions {
        return NetworkQuicTransportOptions(
            keepAliveInterval: 5.0,  // Shorter keep-alive for responsiveness
            connectionIdleTimeout: 30.0,  // Shorter idle timeout
            streamIdleTimeout: 15.0,  // Shorter stream timeout
            maxIdleStreamsPerPeer: 200  // More streams for high throughput
        )
    }
} 