import Foundation

/// Errors that can occur in the Runar system
public enum RunarError: Error, LocalizedError {
    case nodeCreationFailed(String)
    case nodeStartFailed(String)
    case nodeStopFailed(String)
    case serviceRegistrationFailed(String)
    case serviceUnregistrationFailed(String)
    case requestFailed(String)
    case publishFailed(String)
    case subscriptionFailed(String)
    case keychainError(String)
    case serializationError(String)
    case networkError(String)
    case invalidParameters(String)
    case unknownError(String)
    
    public var errorDescription: String? {
        switch self {
        case .nodeCreationFailed(let message):
            return "Node creation failed: \(message)"
        case .nodeStartFailed(let message):
            return "Node start failed: \(message)"
        case .nodeStopFailed(let message):
            return "Node stop failed: \(message)"
        case .serviceRegistrationFailed(let message):
            return "Service registration failed: \(message)"
        case .serviceUnregistrationFailed(let message):
            return "Service unregistration failed: \(message)"
        case .requestFailed(let message):
            return "Request failed: \(message)"
        case .publishFailed(let message):
            return "Publish failed: \(message)"
        case .subscriptionFailed(let message):
            return "Subscription failed: \(message)"
        case .keychainError(let message):
            return "Keychain error: \(message)"
        case .serializationError(let message):
            return "Serialization error: \(message)"
        case .networkError(let message):
            return "Network error: \(message)"
        case .invalidParameters(let message):
            return "Invalid parameters: \(message)"
        case .unknownError(let message):
            return "Unknown error: \(message)"
        }
    }
    
    /// Convert from C error structure
    static func fromCError(_ error: CError) -> RunarError {
        let message = String(cString: error.message)
        let details = error.details.map { String(cString: $0) } ?? ""
        
        switch error.code {
        case RunarErrorCode.invalidParameters.rawValue:
            return .invalidParameters("\(message) \(details)".trimmingCharacters(in: .whitespaces))
        case RunarErrorCode.nodeNotInitialized.rawValue:
            return .nodeCreationFailed("\(message) \(details)".trimmingCharacters(in: .whitespaces))
        case RunarErrorCode.nodeAlreadyStarted.rawValue:
            return .nodeStartFailed("\(message) \(details)".trimmingCharacters(in: .whitespaces))
        case RunarErrorCode.nodeNotStarted.rawValue:
            return .nodeStopFailed("\(message) \(details)".trimmingCharacters(in: .whitespaces))
        case RunarErrorCode.serviceNotFound.rawValue:
            return .serviceRegistrationFailed("\(message) \(details)".trimmingCharacters(in: .whitespaces))
        case RunarErrorCode.serviceRegistrationFailed.rawValue:
            return .serviceRegistrationFailed("\(message) \(details)".trimmingCharacters(in: .whitespaces))
        case RunarErrorCode.keychainError.rawValue:
            return .keychainError("\(message) \(details)".trimmingCharacters(in: .whitespaces))
        case RunarErrorCode.serializationError.rawValue:
            return .serializationError("\(message) \(details)".trimmingCharacters(in: .whitespaces))
        case RunarErrorCode.networkError.rawValue:
            return .networkError("\(message) \(details)".trimmingCharacters(in: .whitespaces))
        default:
            return .unknownError("\(message) \(details)".trimmingCharacters(in: .whitespaces))
        }
    }
    
    /// Convert from C error string (JSON format)
    static func fromCErrorString(_ errorString: String) -> RunarError {
        // Try to parse as JSON first
        if let data = errorString.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            
            let code = json["code"] as? Int32 ?? 0
            let message = json["message"] as? String ?? errorString
            let details = json["details"] as? String ?? ""
            
            switch code {
            case RunarErrorCode.invalidParameters.rawValue:
                return .invalidParameters("\(message) \(details)".trimmingCharacters(in: .whitespaces))
            case RunarErrorCode.nodeNotInitialized.rawValue:
                return .nodeCreationFailed("\(message) \(details)".trimmingCharacters(in: .whitespaces))
            case RunarErrorCode.nodeAlreadyStarted.rawValue:
                return .nodeStartFailed("\(message) \(details)".trimmingCharacters(in: .whitespaces))
            case RunarErrorCode.nodeNotStarted.rawValue:
                return .nodeStopFailed("\(message) \(details)".trimmingCharacters(in: .whitespaces))
            case RunarErrorCode.serviceNotFound.rawValue:
                return .serviceRegistrationFailed("\(message) \(details)".trimmingCharacters(in: .whitespaces))
            case RunarErrorCode.serviceRegistrationFailed.rawValue:
                return .serviceRegistrationFailed("\(message) \(details)".trimmingCharacters(in: .whitespaces))
            case RunarErrorCode.keychainError.rawValue:
                return .keychainError("\(message) \(details)".trimmingCharacters(in: .whitespaces))
            case RunarErrorCode.serializationError.rawValue:
                return .serializationError("\(message) \(details)".trimmingCharacters(in: .whitespaces))
            case RunarErrorCode.networkError.rawValue:
                return .networkError("\(message) \(details)".trimmingCharacters(in: .whitespaces))
            default:
                return .unknownError("\(message) \(details)".trimmingCharacters(in: .whitespaces))
            }
        }
        
        // Fallback to treating as plain string
        return .unknownError(errorString)
    }
} 