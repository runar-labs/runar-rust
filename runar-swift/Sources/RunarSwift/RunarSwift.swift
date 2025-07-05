import Foundation

/// Main Swift API for Runar distributed system
public class RunarSwift {
    
    /// Create a test node configuration
    /// - Returns: A pre-configured node config suitable for testing
    public static func createTestConfig() -> NodeConfig {
        return NodeConfig(
            nodeId: "test-node-\(UUID().uuidString.prefix(8))",
            networkId: "test-network",
            requestTimeoutMs: 5000,
            logLevel: "info"
        )
    }
    
    /// Create a production node configuration
    /// - Parameters:
    ///   - nodeId: Unique identifier for the node
    ///   - networkId: Network identifier
    ///   - requestTimeoutMs: Request timeout in milliseconds (default: 10000)
    ///   - logLevel: Logging level (default: "info")
    /// - Returns: A production-ready node config
    public static func createNodeConfig(
        nodeId: String,
        networkId: String,
        requestTimeoutMs: UInt32 = 10000,
        logLevel: String = "info"
    ) -> NodeConfig {
        return NodeConfig(
            nodeId: nodeId,
            networkId: networkId,
            requestTimeoutMs: requestTimeoutMs,
            logLevel: logLevel
        )
    }
    
    /// Create a new Runar node
    /// - Parameter config: Node configuration
    /// - Returns: A new RunarNode instance
    /// - Throws: RunarError if node creation fails
    public static func createNode(config: NodeConfig) throws -> RunarNode {
        var cConfig = config.toCNodeConfig()
        
        guard let nodePtr = runar_node_create(UnsafeRawPointer(&cConfig)) else {
            throw RunarError.nodeCreationFailed("Failed to create node")
        }
        
        return RunarNode(handle: nodePtr)
    }
}

/// A Runar node instance
public class RunarNode {
    internal let handle: UnsafeMutableRawPointer
    
    init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }
    
    deinit {
        // Cleanup will be handled by the Rust side
    }
    
    /// Start the node
    /// - Parameter completion: Completion handler
    public func start(completion: @escaping (Result<Void, RunarError>) -> Void) {
        pushStartCallback(completion)
        runar_node_start(handle, swift_runar_start_callback_impl)
    }
    
    /// Send a request to a service with string data
    /// - Parameters:
    ///   - path: Service path
    ///   - data: Request data as string
    ///   - completion: Completion handler with response data
    public func request(path: String, data: String, completion: @escaping (Result<String, RunarError>) -> Void) {
        request(path: path, data: data, completion: completion)
    }
    
    /// Send a request to a service with any encodable data
    /// - Parameters:
    ///   - path: Service path
    ///   - data: Request data (will be JSON encoded)
    ///   - completion: Completion handler with response data
    public func request<T: Encodable>(path: String, data: T, completion: @escaping (Result<String, RunarError>) -> Void) {
        do {
            let jsonData = try JSONEncoder().encode(data)
            guard let jsonString = String(data: jsonData, encoding: .utf8) else {
                completion(.failure(.serializationError("Failed to encode data to JSON string")))
                return
            }
            
            pushRequestCallback(completion)
            
            // Ensure both path and data pointers are valid for the duration of the FFI call
            path.withCString { pathCString in
                jsonString.withCString { dataCString in
                    runar_node_request(handle,
                                       pathCString,
                                       dataCString,
                                       UInt(jsonString.utf8.count),
                                       swift_runar_request_callback_impl)
                }
            }
        } catch {
            completion(.failure(.serializationFailed("Failed to encode data: \(error.localizedDescription)")))
        }
    }
    
    /// Send a request to a service with any data type
    /// - Parameters:
    ///   - path: Service path
    ///   - data: Request data (will be converted to JSON)
    ///   - completion: Completion handler with response data
    public func request(path: String, data: Any, completion: @escaping (Result<String, RunarError>) -> Void) {
        do {
            let jsonData = try JSONSerialization.data(withJSONObject: data)
            guard let jsonString = String(data: jsonData, encoding: .utf8) else {
                completion(.failure(.serializationFailed("Failed to convert data to JSON string")))
                return
            }
            
            pushRequestCallback(completion)
            
            // Ensure both path and data pointers are valid for the duration of the FFI call
            path.withCString { pathCString in
                jsonString.withCString { dataCString in
                    runar_node_request(handle,
                                       pathCString,
                                       dataCString,
                                       UInt(jsonString.utf8.count),
                                       swift_runar_request_callback_impl)
                }
            }
        } catch {
            completion(.failure(.serializationFailed("Failed to serialize data: \(error.localizedDescription)")))
        }
    }
}

/// Configuration for a Runar node
public struct NodeConfig {
    public let nodeId: String
    public let networkId: String
    public let requestTimeoutMs: UInt32
    public let logLevel: String
    
    public init(
        nodeId: String,
        networkId: String,
        requestTimeoutMs: UInt32 = 10000,
        logLevel: String = "info"
    ) {
        self.nodeId = nodeId
        self.networkId = networkId
        self.requestTimeoutMs = requestTimeoutMs
        self.logLevel = logLevel
    }
    
    func toCNodeConfig() -> CNodeConfig {
        let nodeIdPtr = nodeId.withCString { $0 }
        let networkIdPtr = networkId.withCString { $0 }
        return CNodeConfig(node_id: nodeIdPtr, default_network_id: networkIdPtr)
    }
}
