import Foundation

// MARK: - Encryption Types

/// Information about a label's key mapping
public struct LabelKeyInfo {
    public let profileIds: [String]
    public let networkId: String?
    
    public init(profileIds: [String], networkId: String?) {
        self.profileIds = profileIds
        self.networkId = networkId
    }
}

/// Protocol for resolving labels to key information
public protocol LabelResolver {
    /// Resolve a field label to key information
    func resolveLabel(_ label: String) -> LabelKeyInfo?
} 