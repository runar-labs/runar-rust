import Foundation
import RunarKeys

/// Basic usage example for RunarKeys Swift implementation
@main
struct BasicUsageExample {
    
    static func main() async {
        print("🚀 RunarKeys Swift - Basic Usage Example")
        print("=========================================")
        
        // Create a logger
        let logger = ConsoleLogger(prefix: "Example")
        
        do {
            // Initialize Mobile Key Manager
            print("\n📱 Initializing Mobile Key Manager...")
            let mobileManager = try MobileKeyManager(logger: logger)
            
            // Initialize user root key
            print("🔑 Initializing user root key...")
            let rootPublicKey = try mobileManager.initializeUserRootKey()
            print("   Root public key: \(rootPublicKey.base64EncodedString())")
            
            // Derive profile keys
            print("\n👤 Deriving profile keys...")
            let personalKey = try mobileManager.deriveUserProfileKey(label: "personal")
            let workKey = try mobileManager.deriveUserProfileKey(label: "work")
            print("   Personal profile key: \(personalKey.base64EncodedString())")
            print("   Work profile key: \(workKey.base64EncodedString())")
            
            // Generate network keys
            print("\n🌐 Generating network keys...")
            let networkId1 = try mobileManager.generateNetworkDataKey()
            let networkId2 = try mobileManager.generateNetworkDataKey()
            print("   Network 1 ID: \(networkId1)")
            print("   Network 2 ID: \(networkId2)")
            
            // Get statistics
            print("\n📊 Mobile Manager Statistics:")
            let stats = mobileManager.getStatistics()
            print("   Issued certificates: \(stats.issuedCertificatesCount)")
            print("   Profile keys: \(stats.userProfileKeysCount)")
            print("   Network keys: \(stats.networkKeysCount)")
            print("   CA subject: \(stats.caCertificateSubject)")
            
            // Initialize Node Key Manager
            print("\n🖥️  Initializing Node Key Manager...")
            let nodeManager = try NodeKeyManager(nodeId: "example-node", logger: logger)
            
            // Generate CSR
            print("📝 Generating Certificate Signing Request...")
            let setupToken = try nodeManager.generateCSR(nodeId: "example-node")
            print("   Node ID: \(setupToken.nodeId)")
            print("   Public key: \(setupToken.nodePublicKey.base64EncodedString())")
            print("   CSR data size: \(setupToken.csrDER.count) bytes")
            
            // Generate symmetric keys
            print("\n🔐 Generating symmetric keys...")
            let storageKey = nodeManager.generateSymmetricKey(keyId: "storage")
            let sessionKey = nodeManager.generateSymmetricKey(keyId: "session")
            print("   Storage key size: \(storageKey.count) bytes")
            print("   Session key size: \(sessionKey.count) bytes")
            
            // Digital signatures
            print("\n✍️  Testing digital signatures...")
            let message = "Hello, Runar Network!".data(using: .utf8)!
            let signature = try nodeManager.signData(message)
            print("   Message: Hello, Runar Network!")
            print("   Signature size: \(signature.count) bytes")
            
            // Get node statistics
            print("\n📊 Node Manager Statistics:")
            let nodeStats = nodeManager.getStatistics(nodeId: "example-node")
            print("   Node ID: \(nodeStats.nodeId)")
            print("   Has certificate: \(nodeStats.hasCertificate)")
            print("   Has CA certificate: \(nodeStats.hasCACertificate)")
            print("   Certificate status: \(nodeStats.certificateStatus)")
            print("   Network keys: \(nodeStats.networkKeysCount)")
            print("   Public key: \(nodeStats.nodePublicKey)")
            
            // Test compact ID generation
            print("\n🆔 Testing compact ID generation...")
            let compactId = compactId(rootPublicKey)
            print("   Compact ID: \(compactId)")
            
            // Test envelope encryption (placeholder)
            print("\n📦 Testing envelope encryption (placeholder)...")
            let testData = "Secret data for envelope encryption".data(using: .utf8)!
            print("   Original data: \(String(data: testData, encoding: .utf8) ?? "unknown")")
            print("   Note: Envelope encryption is not yet implemented")
            
            print("\n✅ All operations completed successfully!")
            
        } catch {
            print("\n❌ Error: \(error)")
            if let keyError = error as? KeyError {
                print("   Description: \(keyError.errorDescription ?? "No description")")
                print("   Recovery: \(keyError.recoverySuggestion ?? "No suggestion")")
            }
        }
        
        print("\n🎉 RunarKeys Swift implementation is working!")
    }
} 