import Foundation
import os.log

/// Logger protocol for RunarKeys
public protocol Logger: Sendable {
    func debug(_ message: String)
    func info(_ message: String)
    func warn(_ message: String)
    func error(_ message: String)
}

/// Simple logger implementation for RunarKeys
public class SimpleLogger: @unchecked Sendable, Logger {
    private let subsystem: String
    private let category: String
    private let osLogger: OSLog
    
    public init(subsystem: String = "com.runar.keys", category: String = "default") {
        self.subsystem = subsystem
        self.category = category
        self.osLogger = OSLog(subsystem: subsystem, category: category)
    }
    
    public func debug(_ message: String) {
        os_log(.debug, log: osLogger, "%{public}@", message)
    }
    
    public func info(_ message: String) {
        os_log(.info, log: osLogger, "%{public}@", message)
    }
    
    public func warn(_ message: String) {
        os_log(.error, log: osLogger, "WARNING: %{public}@", message)
    }
    
    public func error(_ message: String) {
        os_log(.fault, log: osLogger, "ERROR: %{public}@", message)
    }
}

/// Console logger for development and testing
public class ConsoleLogger: @unchecked Sendable, Logger {
    private let prefix: String
    
    public init(prefix: String = "RunarKeys") {
        self.prefix = prefix
    }
    
    public func debug(_ message: String) {
        print("[\(prefix)] DEBUG: \(message)")
    }
    
    public func info(_ message: String) {
        print("[\(prefix)] INFO: \(message)")
    }
    
    public func warn(_ message: String) {
        print("[\(prefix)] WARN: \(message)")
    }
    
    public func error(_ message: String) {
        print("[\(prefix)] ERROR: \(message)")
    }
} 