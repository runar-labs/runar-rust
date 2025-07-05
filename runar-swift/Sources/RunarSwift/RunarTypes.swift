import Foundation

// MARK: - C Types

/// C error codes from the Rust FFI
public enum RunarErrorCode: Int32 {
    case success = 0
    case invalidParameters = 1
    case nodeNotInitialized = 2
    case nodeAlreadyStarted = 3
    case nodeNotStarted = 4
    case serviceNotFound = 5
    case serviceRegistrationFailed = 6
    case keychainError = 7
    case serializationError = 8
    case networkError = 9
}

/// C error structure from the Rust FFI (simplified for JSON)
public struct CError {
    public let code: Int32
    public let message: UnsafePointer<Int8>
    public let details: UnsafePointer<Int8>?
}

/// C node configuration structure
public struct CNodeConfig {
    public let node_id: UnsafePointer<Int8>
    public let default_network_id: UnsafePointer<Int8>
}

/// C node information structure (simplified for JSON)
public struct CNodeInfo {
    public let node_id: UnsafePointer<Int8>
    public let network_id: UnsafePointer<Int8>
    public let is_running: Int32
    public let peer_count: Int32
    public let service_count: Int32
}

/// C data result structure (simplified for JSON)
public struct CDataResult {
    public let data: UnsafePointer<Int8>  // JSON string
    public let data_len: UInt
    public let error: UnsafePointer<Int8>? // JSON error string
}

// MARK: - Callback Types (Simplified for C compatibility)

/// Callback for node start operations
public typealias StartCallback = @convention(c) (UnsafePointer<Int8>?, UnsafePointer<Int8>?) -> Void

/// Callback for node stop operations
public typealias StopCallback = @convention(c) (UnsafePointer<Int8>?, UnsafePointer<Int8>?) -> Void

/// Callback for request operations
public typealias RequestCallback = @convention(c) (UnsafePointer<Int8>, UInt, UnsafePointer<Int8>?) -> Void

/// Callback for publish operations
public typealias PublishCallback = @convention(c) (UnsafePointer<Int8>?, UnsafePointer<Int8>?) -> Void

/// Callback for event subscriptions
public typealias EventCallback = @convention(c) (UnsafePointer<Int8>, UnsafePointer<Int8>, UInt) -> Void

/// Callback for service operations
public typealias ServiceCallback = @convention(c) (Int32, UnsafePointer<Int8>?) -> Void

// MARK: - C Function Declarations

/// Initialize the Runar runtime
@_silgen_name("runar_runtime_initialize")
public func runar_runtime_initialize() -> CError

/// Handle background transition
@_silgen_name("runar_runtime_handle_background")
public func runar_runtime_handle_background() -> CError

/// Handle foreground transition
@_silgen_name("runar_runtime_handle_foreground")
public func runar_runtime_handle_foreground() -> CError

/// Create a new node
@_silgen_name("runar_node_create")
public func runar_node_create(_ config: UnsafeRawPointer) -> UnsafeMutableRawPointer?

/// Start a node
@_silgen_name("runar_node_start")
public func runar_node_start(_ node: UnsafeMutableRawPointer, _ callback: StartCallback)

/// Stop a node
@_silgen_name("runar_node_stop")
public func runar_node_stop(_ node: UnsafeMutableRawPointer, _ callback: StopCallback)

/// Send a request to a service
@_silgen_name("runar_node_request")
public func runar_node_request(
    _ node: UnsafeMutableRawPointer,
    _ path: UnsafePointer<Int8>,
    _ data: UnsafePointer<Int8>,  // JSON string
    _ data_len: UInt,
    _ callback: RequestCallback
)

/// Publish data to a topic
@_silgen_name("runar_node_publish")
public func runar_node_publish(
    _ node: UnsafeMutablePointer<CNode>,
    _ topic: UnsafePointer<Int8>,
    _ data: UnsafePointer<Int8>,  // JSON string
    _ data_len: UInt,
    _ callback: PublishCallback
)

/// Subscribe to events on a topic
@_silgen_name("runar_node_subscribe")
public func runar_node_subscribe(
    _ node: UnsafeMutablePointer<CNode>,
    _ topic: UnsafePointer<Int8>,
    _ callback: EventCallback
) -> UnsafePointer<Int8>  // Returns subscription ID as string

/// Get node information
@_silgen_name("runar_node_get_info")
public func runar_node_get_info(_ node: UnsafeMutablePointer<CNode>) -> CNodeInfo

/// Register a service
@_silgen_name("runar_service_register")
public func runar_service_register(
    _ path: UnsafePointer<Int8>,
    _ name: UnsafePointer<Int8>,
    _ version: UnsafePointer<Int8>,
    _ description: UnsafePointer<Int8>,
    _ actionHandler: @escaping (UnsafePointer<Int8>, UnsafePointer<Int8>, UInt) -> UnsafePointer<Int8>,
    _ eventHandler: @escaping (UnsafePointer<Int8>, UnsafePointer<Int8>, UInt) -> Void,
    _ callback: ServiceCallback
)

/// Unregister a service
@_silgen_name("runar_service_unregister")
public func runar_service_unregister(_ path: UnsafePointer<Int8>, _ callback: ServiceCallback)

/// Setup lifecycle observers
@_silgen_name("runar_lifecycle_setup_observers")
public func runar_lifecycle_setup_observers(_ node: UnsafeMutablePointer<CNode>) -> CError

/// Handle background transition
@_silgen_name("runar_lifecycle_handle_background")
public func runar_lifecycle_handle_background(_ node: UnsafeMutablePointer<CNode>) -> CError

/// Handle foreground transition
@_silgen_name("runar_lifecycle_handle_foreground")
public func runar_lifecycle_handle_foreground(_ node: UnsafeMutablePointer<CNode>) -> CError

/// Handle memory warning
@_silgen_name("runar_lifecycle_handle_memory_warning")
public func runar_lifecycle_handle_memory_warning(_ node: UnsafeMutablePointer<CNode>) -> CError

// MARK: - C Node Type

/// Opaque C node type
public struct CNode {
    // This is an opaque type from the Rust side
} 