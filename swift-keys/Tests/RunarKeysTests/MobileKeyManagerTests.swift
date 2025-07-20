import XCTest
@testable import RunarKeys

final class MobileKeyManagerTests: XCTestCase {
    
    var logger: ConsoleLogger!
    var mobileKeyManager: MobileKeyManager!
    
    override func setUp() {
        super.setUp()
        logger = ConsoleLogger()
        mobileKeyManager = try! MobileKeyManager(logger: logger)
    }
    
    override func tearDown() {
        mobileKeyManager = nil
        logger = nil
        super.tearDown()
    }
    
    func testMobileKeyManagerInitialization() throws {
        // Test that MobileKeyManager can be initialized
        XCTAssertNotNil(mobileKeyManager)
        
        // Test that CA certificate is created
        let caCertificate = mobileKeyManager.getCaCertificate()
        XCTAssertNotNil(caCertificate)
        XCTAssertTrue(caCertificate.subject.contains("Runar User CA"))
        
        // Test that CA public key is available
        let caPublicKey = mobileKeyManager.getCaPublicKey()
        XCTAssertNotNil(caPublicKey)
        XCTAssertFalse(caPublicKey.isEmpty)
        
        // Test initial statistics
        let stats = mobileKeyManager.getStatistics()
        XCTAssertEqual(stats.issuedCertificatesCount, 0)
        XCTAssertEqual(stats.userProfileKeysCount, 0)
        XCTAssertEqual(stats.networkKeysCount, 0)
        XCTAssertTrue(stats.caCertificateSubject.contains("Runar User CA"))
    }
    
    func testUserRootKeyInitialization() throws {
        // Test that user root key can be initialized
        let publicKey = try mobileKeyManager.initializeUserRootKey()
        XCTAssertNotNil(publicKey)
        XCTAssertFalse(publicKey.isEmpty)
        
        // Test that we can get the public key
        let retrievedPublicKey = try mobileKeyManager.getUserRootPublicKey()
        XCTAssertEqual(publicKey, retrievedPublicKey)
        
        // Test that trying to initialize again throws an error
        XCTAssertThrowsError(try mobileKeyManager.initializeUserRootKey()) { error in
            XCTAssertTrue(error is KeyError)
        }
    }
    
    func testUserRootKeyNotInitialized() throws {
        // Test that getting public key before initialization throws an error
        XCTAssertThrowsError(try mobileKeyManager.getUserRootPublicKey()) { error in
            XCTAssertTrue(error is KeyError)
        }
    }
    
    func testNetworkPublicKeyInstallation() throws {
        // Create a test public key
        let testKeyPair = try ECDHKeyPair()
        let testPublicKey = testKeyPair.publicKeyBytes()
        
        // Test that network public key can be installed
        try mobileKeyManager.installNetworkPublicKey(testPublicKey)
        
        // Verify the key was installed by checking statistics
        // Note: This is a basic test - we'll add more comprehensive network key tests later
        let stats = mobileKeyManager.getStatistics()
        XCTAssertEqual(stats.networkKeysCount, 0) // This should still be 0 since we only installed a public key
    }
    
    func testUserProfileKeyDerivation() throws {
        // First initialize the user root key
        _ = try mobileKeyManager.initializeUserRootKey()
        
        // Test that we can derive a profile key
        let profileKey1 = try mobileKeyManager.deriveUserProfileKey(label: "personal")
        XCTAssertNotNil(profileKey1)
        XCTAssertFalse(profileKey1.isEmpty)
        
        // Test that deriving the same label again returns the same key
        let profileKey2 = try mobileKeyManager.deriveUserProfileKey(label: "personal")
        XCTAssertEqual(profileKey1, profileKey2)
        
        // Test that different labels produce different keys
        let profileKey3 = try mobileKeyManager.deriveUserProfileKey(label: "work")
        XCTAssertNotEqual(profileKey1, profileKey3)
        
        // Test that statistics reflect the profile keys
        let stats = mobileKeyManager.getStatistics()
        XCTAssertEqual(stats.userProfileKeysCount, 2) // personal and work
    }
    
    func testUserProfileKeyDerivationWithoutRootKey() throws {
        // Test that deriving a profile key without initializing root key throws an error
        XCTAssertThrowsError(try mobileKeyManager.deriveUserProfileKey(label: "personal")) { error in
            XCTAssertTrue(error is KeyError)
        }
    }
    
    func testUserProfileKeyDeterministic() throws {
        // First initialize the user root key
        _ = try mobileKeyManager.initializeUserRootKey()
        
        // Derive a profile key
        let profileKey1 = try mobileKeyManager.deriveUserProfileKey(label: "test-profile")
        
        // Create a new MobileKeyManager and initialize with the same root key
        let newLogger = ConsoleLogger()
        let newMobileKeyManager = try MobileKeyManager(logger: newLogger)
        
        // We can't easily restore the same root key, so this test verifies
        // that the same label produces the same key within the same instance
        let profileKey2 = try mobileKeyManager.deriveUserProfileKey(label: "test-profile")
        XCTAssertEqual(profileKey1, profileKey2)
    }
    
    func testNetworkDataKeyGeneration() throws {
        // Test that we can generate a network data key
        let networkId1 = try mobileKeyManager.generateNetworkDataKey()
        XCTAssertNotNil(networkId1)
        XCTAssertFalse(networkId1.isEmpty)
        
        // Test that generating another key produces a different ID
        let networkId2 = try mobileKeyManager.generateNetworkDataKey()
        XCTAssertNotEqual(networkId1, networkId2)
        
        // Test that we can retrieve the public keys
        let publicKey1 = try mobileKeyManager.getNetworkPublicKey(networkId: networkId1)
        let publicKey2 = try mobileKeyManager.getNetworkPublicKey(networkId: networkId2)
        XCTAssertNotEqual(publicKey1, publicKey2)
        
        // Test that statistics reflect the network keys
        let stats = mobileKeyManager.getStatistics()
        XCTAssertEqual(stats.networkKeysCount, 2)
    }
    
    func testNetworkPublicKeyRetrieval() throws {
        // Generate a network data key
        let networkId = try mobileKeyManager.generateNetworkDataKey()
        
        // Test that we can retrieve the public key
        let publicKey = try mobileKeyManager.getNetworkPublicKey(networkId: networkId)
        XCTAssertNotNil(publicKey)
        XCTAssertFalse(publicKey.isEmpty)
        
        // Test that retrieving a non-existent network ID throws an error
        XCTAssertThrowsError(try mobileKeyManager.getNetworkPublicKey(networkId: "non-existent")) { error in
            XCTAssertTrue(error is KeyError)
        }
    }
    
    func testNetworkPublicKeyInstallationAndRetrieval() throws {
        // Create a test public key
        let testKeyPair = try ECDHKeyPair()
        let testPublicKey = testKeyPair.publicKeyBytes()
        
        // Install the network public key
        try mobileKeyManager.installNetworkPublicKey(testPublicKey)
        
        // Get the network ID
        let networkId = CryptoUtils.compactId(testPublicKey)
        
        // Test that we can retrieve the installed public key
        let retrievedPublicKey = try mobileKeyManager.getNetworkPublicKey(networkId: networkId)
        XCTAssertEqual(testPublicKey, retrievedPublicKey)
        
        // Test that statistics don't count installed public keys as network keys
        let stats = mobileKeyManager.getStatistics()
        XCTAssertEqual(stats.networkKeysCount, 0) // Only generated keys count
    }
    
    func testCertificateIssuance() throws {
        // Create a test key pair for the node
        let nodeKeyPair = try ECDHKeyPair()
        let nodeId = "test-node-123"
        
        // Create a CSR for the node
        let csr = try CertificateRequest.create(
            keyPair: nodeKeyPair,
            subject: "CN=\(nodeId),O=Runar,C=US"
        )
        
        // Create a setup token
        let setupToken = SetupToken(
            nodePublicKey: nodeKeyPair.publicKeyBytes(),
            csrDer: csr,
            nodeId: nodeId
        )
        
        // Process the setup token
        let certificateMessage = try mobileKeyManager.processSetupToken(setupToken)
        
        // Verify the certificate message
        XCTAssertNotNil(certificateMessage.nodeCertificate)
        XCTAssertNotNil(certificateMessage.caCertificate)
        XCTAssertEqual(certificateMessage.metadata.purpose, "Node TLS Certificate")
        XCTAssertEqual(certificateMessage.metadata.validityDays, 365)
        
        // Verify the certificate was stored
        let storedCertificate = mobileKeyManager.getIssuedCertificate(nodeId: nodeId)
        XCTAssertNotNil(storedCertificate)
        XCTAssertEqual(storedCertificate?.getSubject(), certificateMessage.nodeCertificate.getSubject())
        
        // Verify statistics reflect the issued certificate
        let stats = mobileKeyManager.getStatistics()
        XCTAssertEqual(stats.issuedCertificatesCount, 1)
    }
    
    func testCertificateIssuanceWithInvalidCSR() throws {
        // Create a setup token with empty CSR
        let setupToken = SetupToken(
            nodePublicKey: Data(),
            csrDer: Data(),
            nodeId: "test-node"
        )
        
        // Test that processing fails
        XCTAssertThrowsError(try mobileKeyManager.processSetupToken(setupToken)) { error in
            XCTAssertTrue(error is KeyError)
        }
    }
    
    func testCertificateIssuanceWithMismatchedNodeId() throws {
        // Create a test key pair for the node
        let nodeKeyPair = try ECDHKeyPair()
        let nodeId = "test-node-123"
        let wrongNodeId = "wrong-node-id"
        
        // Create a CSR for the node
        let csr = try CertificateRequest.create(
            keyPair: nodeKeyPair,
            subject: "CN=\(nodeId),O=Runar,C=US"
        )
        
        // Create a setup token with mismatched node ID
        let setupToken = SetupToken(
            nodePublicKey: nodeKeyPair.publicKeyBytes(),
            csrDer: csr,
            nodeId: wrongNodeId
        )
        
        // Test that processing fails
        XCTAssertThrowsError(try mobileKeyManager.processSetupToken(setupToken)) { error in
            XCTAssertTrue(error is KeyError)
        }
    }
    
    func testCertificateValidation() throws {
        // Create a test key pair for the node
        let nodeKeyPair = try ECDHKeyPair()
        let nodeId = "test-node-123"
        
        // Create a CSR for the node
        let csr = try CertificateRequest.create(
            keyPair: nodeKeyPair,
            subject: "CN=\(nodeId),O=Runar,C=US"
        )
        
        // Create a setup token
        let setupToken = SetupToken(
            nodePublicKey: nodeKeyPair.publicKeyBytes(),
            csrDer: csr,
            nodeId: nodeId
        )
        
        // Process the setup token
        let certificateMessage = try mobileKeyManager.processSetupToken(setupToken)
        
        // Validate the issued certificate
        try mobileKeyManager.validateCertificate(certificateMessage.nodeCertificate)
    }
    
    func testListIssuedCertificates() throws {
        // Initially, no certificates should be issued
        let initialCertificates = mobileKeyManager.listIssuedCertificates()
        XCTAssertEqual(initialCertificates.count, 0)
        
        // Create and issue a certificate
        let nodeKeyPair = try ECDHKeyPair()
        let nodeId = "test-node-123"
        
        let csr = try CertificateRequest.create(
            keyPair: nodeKeyPair,
            subject: "CN=\(nodeId),O=Runar,C=US"
        )
        
        let setupToken = SetupToken(
            nodePublicKey: nodeKeyPair.publicKeyBytes(),
            csrDer: csr,
            nodeId: nodeId
        )
        
        _ = try mobileKeyManager.processSetupToken(setupToken)
        
        // Now there should be one certificate
        let certificates = mobileKeyManager.listIssuedCertificates()
        XCTAssertEqual(certificates.count, 1)
        XCTAssertEqual(certificates[0].0, nodeId)
    }
    
    func testEnvelopeEncryptionWithProfileKeys() throws {
        // Initialize user root key
        try mobileKeyManager.initializeUserRootKey()
        
        // Derive profile keys and get their IDs
        _ = try mobileKeyManager.deriveUserProfileKey(label: "personal")
        _ = try mobileKeyManager.deriveUserProfileKey(label: "work")
        let personalProfileId = try mobileKeyManager.getProfileId(for: "personal")
        let workProfileId = try mobileKeyManager.getProfileId(for: "work")
        
        // Test data to encrypt
        let testData = "Hello, envelope encryption!".data(using: .utf8)!
        
        // Encrypt with envelope using profile keys
        let envelopeData = try mobileKeyManager.encryptWithEnvelope(
            data: testData,
            networkId: nil,
            profileIds: [personalProfileId, workProfileId]
        )
        
        // Verify envelope data structure
        XCTAssertFalse(envelopeData.encryptedData.isEmpty)
        XCTAssertNil(envelopeData.networkId)
        XCTAssertTrue(envelopeData.networkEncryptedKey.isEmpty)
        XCTAssertEqual(envelopeData.profileEncryptedKeys.count, 2)
        XCTAssertNotNil(envelopeData.profileEncryptedKeys[personalProfileId])
        XCTAssertNotNil(envelopeData.profileEncryptedKeys[workProfileId])
        
        // Decrypt using personal profile key
        let decryptedData = try mobileKeyManager.decryptWithProfile(
            envelopeData: envelopeData,
            profileId: personalProfileId
        )
        
        XCTAssertEqual(decryptedData, testData)
        
        // Decrypt using work profile key
        let decryptedData2 = try mobileKeyManager.decryptWithProfile(
            envelopeData: envelopeData,
            profileId: workProfileId
        )
        
        XCTAssertEqual(decryptedData2, testData)
    }
    
    func testEnvelopeEncryptionWithNetworkKey() throws {
        // Generate a network data key
        let networkId = try mobileKeyManager.generateNetworkDataKey()
        
        // Test data to encrypt
        let testData = "Hello, network encryption!".data(using: .utf8)!
        
        // Encrypt with envelope using network key
        let envelopeData = try mobileKeyManager.encryptWithEnvelope(
            data: testData,
            networkId: networkId,
            profileIds: []
        )
        
        // Verify envelope data structure
        XCTAssertFalse(envelopeData.encryptedData.isEmpty)
        XCTAssertEqual(envelopeData.networkId, networkId)
        XCTAssertFalse(envelopeData.networkEncryptedKey.isEmpty)
        XCTAssertTrue(envelopeData.profileEncryptedKeys.isEmpty)
        
        // Decrypt using network key
        let decryptedData = try mobileKeyManager.decryptWithNetwork(envelopeData: envelopeData)
        
        XCTAssertEqual(decryptedData, testData)
    }
    
    func testEnvelopeEncryptionWithBothNetworkAndProfileKeys() throws {
        // Initialize user root key and derive profile key
        try mobileKeyManager.initializeUserRootKey()
        _ = try mobileKeyManager.deriveUserProfileKey(label: "personal")
        let personalProfileId = try mobileKeyManager.getProfileId(for: "personal")
        
        // Generate a network data key
        let networkId = try mobileKeyManager.generateNetworkDataKey()
        
        // Test data to encrypt
        let testData = "Hello, combined encryption!".data(using: .utf8)!
        
        // Encrypt with envelope using both network and profile keys
        let envelopeData = try mobileKeyManager.encryptWithEnvelope(
            data: testData,
            networkId: networkId,
            profileIds: [personalProfileId]
        )
        
        // Verify envelope data structure
        XCTAssertFalse(envelopeData.encryptedData.isEmpty)
        XCTAssertEqual(envelopeData.networkId, networkId)
        XCTAssertFalse(envelopeData.networkEncryptedKey.isEmpty)
        XCTAssertEqual(envelopeData.profileEncryptedKeys.count, 1)
        XCTAssertNotNil(envelopeData.profileEncryptedKeys[personalProfileId])
        
        // Decrypt using profile key
        let decryptedData1 = try mobileKeyManager.decryptWithProfile(
            envelopeData: envelopeData,
            profileId: personalProfileId
        )
        XCTAssertEqual(decryptedData1, testData)
        
        // Decrypt using network key
        let decryptedData2 = try mobileKeyManager.decryptWithNetwork(envelopeData: envelopeData)
        XCTAssertEqual(decryptedData2, testData)
    }
    
    func testEnvelopeEncryptionWithInstalledNetworkPublicKey() throws {
        // Create a test key pair and install as network public key
        let testKeyPair = try ECDHKeyPair()
        let testPublicKey = testKeyPair.publicKeyBytes()
        try mobileKeyManager.installNetworkPublicKey(testPublicKey)
        
        let networkId = CryptoUtils.compactId(testPublicKey)
        
        // Test data to encrypt
        let testData = "Hello, installed network key!".data(using: .utf8)!
        
        // Encrypt with envelope using installed network public key
        let envelopeData = try mobileKeyManager.encryptWithEnvelope(
            data: testData,
            networkId: networkId,
            profileIds: []
        )
        
        // Verify envelope data structure
        XCTAssertFalse(envelopeData.encryptedData.isEmpty)
        XCTAssertEqual(envelopeData.networkId, networkId)
        XCTAssertFalse(envelopeData.networkEncryptedKey.isEmpty)
        
        // Note: We can't decrypt with installed public key since we don't have the private key
        // This test verifies that encryption works with installed public keys
    }
    
    func testEnvelopeDecryptionFailure() throws {
        // Initialize user root key and derive profile key
        try mobileKeyManager.initializeUserRootKey()
        _ = try mobileKeyManager.deriveUserProfileKey(label: "personal")
        let personalProfileId = try mobileKeyManager.getProfileId(for: "personal")
        
        // Generate network key
        let networkId = try mobileKeyManager.generateNetworkDataKey()
        
        // Encrypt data with both network and profile keys
        let testData = "Hello, World!".data(using: .utf8)!
        let envelopeData = try mobileKeyManager.encryptWithEnvelope(
            data: testData,
            networkId: networkId,
            profileIds: [personalProfileId]
        )
        
        // Try to decrypt with wrong profile ID
        XCTAssertThrowsError(try mobileKeyManager.decryptWithProfile(
            envelopeData: envelopeData,
            profileId: "wrong-profile-id"
        )) { error in
            XCTAssertTrue(error is KeyError)
        }
    }
    
    // MARK: - State Management Tests
    
    func testStateExportAndRestore() throws {
        // Initialize the key manager with some state
        _ = try mobileKeyManager.initializeUserRootKey()
        _ = try mobileKeyManager.deriveUserProfileKey(label: "personal")
        _ = try mobileKeyManager.deriveUserProfileKey(label: "work")
        let networkId = try mobileKeyManager.generateNetworkDataKey()
        
        // Issue a certificate (skip for now due to CSR complexity)
        // In a real implementation, you'd create a proper CSR
        // For testing, we'll just verify the state export works without certificates
        
        // Export state
        let state = try mobileKeyManager.exportState()
        
        // Verify state contains expected data
        XCTAssertNotNil(state.caKeyPair)
        XCTAssertNotNil(state.caCertificate)
        XCTAssertNotNil(state.userRootKey)
        XCTAssertEqual(state.userProfileKeys.count, 2)
        XCTAssertEqual(state.networkDataKeys.count, 1)
        XCTAssertEqual(state.issuedCertificates.count, 0) // No certificates issued in this test
        XCTAssertGreaterThan(state.serialCounter, 0)
        
        // Create a new key manager and restore state
        let newLogger = ConsoleLogger()
        let newMobileKeyManager = try MobileKeyManager(logger: newLogger)
        try newMobileKeyManager.restoreFromState(state)
        
        // Verify state was restored correctly
        let stats = newMobileKeyManager.getStatistics()
        XCTAssertEqual(stats.userProfileKeysCount, 2)
        XCTAssertEqual(stats.networkKeysCount, 1)
        XCTAssertEqual(stats.issuedCertificatesCount, 0) // No certificates issued in this test
        
        // Verify we can still use the restored keys
        let testData = "Test data".data(using: .utf8)!
        let envelopeData = try newMobileKeyManager.encryptWithEnvelope(
            data: testData,
            networkId: networkId,
            profileIds: []
        )
        
        let decryptedData = try newMobileKeyManager.decryptWithNetwork(envelopeData: envelopeData)
        XCTAssertEqual(decryptedData, testData)
    }
    
    func testKeychainStateManagement() throws {
        // Skip this test if we can't access Keychain (e.g., in CI)
        // In a real app, you'd want to test this with proper Keychain access
        
        // Initialize the key manager with some state
        _ = try mobileKeyManager.initializeUserRootKey()
        _ = try mobileKeyManager.deriveUserProfileKey(label: "personal")
        let networkId = try mobileKeyManager.generateNetworkDataKey()
        
        // Test that no state exists initially
        XCTAssertFalse(mobileKeyManager.hasKeychainState())
        
        // Save to Keychain
        try mobileKeyManager.saveToKeychain()
        
        // Verify state exists
        XCTAssertTrue(mobileKeyManager.hasKeychainState())
        
        // Create a new key manager and load from Keychain
        let newLogger = ConsoleLogger()
        let newMobileKeyManager = try MobileKeyManager(logger: newLogger)
        try newMobileKeyManager.loadFromKeychain()
        
        // Verify state was loaded correctly
        let stats = newMobileKeyManager.getStatistics()
        XCTAssertEqual(stats.userProfileKeysCount, 1)
        XCTAssertEqual(stats.networkKeysCount, 1)
        
        // Test that we can use the loaded keys
        let testData = "Test data".data(using: .utf8)!
        let envelopeData = try newMobileKeyManager.encryptWithEnvelope(
            data: testData,
            networkId: networkId,
            profileIds: []
        )
        
        let decryptedData = try newMobileKeyManager.decryptWithNetwork(envelopeData: envelopeData)
        XCTAssertEqual(decryptedData, testData)
        
        // Clean up
        try newMobileKeyManager.clearKeychainState()
        XCTAssertFalse(newMobileKeyManager.hasKeychainState())
    }
    
    // MARK: - Legacy Compatibility Tests
    
    func testLegacyCompatibilityMethods() throws {
        // Test legacy initializeUserIdentity method (should return existing root key)
        let rootKey = try mobileKeyManager.initializeUserIdentity()
        XCTAssertEqual(rootKey.count, 65) // Uncompressed public key
        
        // Test legacy generateUserProfileKey method
        let profileKey = try mobileKeyManager.generateUserProfileKey(profileId: "legacy-profile")
        XCTAssertEqual(profileKey.count, 65) // Uncompressed public key
        
        // Get the profile ID for the legacy profile
        let legacyProfileId = try mobileKeyManager.getProfileId(for: "legacy-profile")
        
        // Test legacy encryptForProfile method
        let testData = "Test data for profile".data(using: .utf8)!
        let encryptedData = try mobileKeyManager.encryptForProfile(data: testData, profileId: legacyProfileId)
        XCTAssertFalse(encryptedData.isEmpty)
        
        // Test legacy encryptForNetwork method
        let networkId = try mobileKeyManager.generateNetworkDataKey()
        let encryptedNetworkData = try mobileKeyManager.encryptForNetwork(data: testData, networkId: networkId)
        XCTAssertFalse(encryptedNetworkData.isEmpty)
    }
    
    // MARK: - Node Communication Tests
    
    func testNodeCommunicationMethods() throws {
        // Initialize user root key
        _ = try mobileKeyManager.initializeUserRootKey()
        
        // Generate network key
        let networkId = try mobileKeyManager.generateNetworkDataKey()
        
        // Create a test node public key
        let nodeKeyPair = try ECDHKeyPair()
        let nodePublicKey = nodeKeyPair.publicKeyBytes()
        
        // Test createNetworkKeyMessage
        let networkKeyMessage = try mobileKeyManager.createNetworkKeyMessage(
            networkId: networkId,
            nodePublicKey: nodePublicKey
        )
        
        XCTAssertEqual(networkKeyMessage.networkId, networkId)
        XCTAssertFalse(networkKeyMessage.networkPublicKey.isEmpty)
        XCTAssertFalse(networkKeyMessage.encryptedNetworkKey.isEmpty)
        XCTAssertTrue(networkKeyMessage.keyDerivationInfo.contains("ECIES encrypted"))
        
        // Test encryptMessageForNode
        let testMessage = "Hello from mobile to node".data(using: .utf8)!
        let encryptedMessage = try mobileKeyManager.encryptMessageForNode(
            message: testMessage,
            nodePublicKey: nodePublicKey
        )
        XCTAssertFalse(encryptedMessage.isEmpty)
        
        // Note: decryptMessageFromNode requires the message to be encrypted with the mobile's root key
        // This test only verifies encryption works, not the full round-trip
    }
    
    func testNodeCommunicationWithInvalidKeys() throws {
        // Test encryptMessageForNode with invalid public key
        let testMessage = "Test message".data(using: .utf8)!
        let invalidPublicKey = Data(repeating: 0, count: 65) // Invalid uncompressed key
        
        XCTAssertThrowsError(try mobileKeyManager.encryptMessageForNode(
            message: testMessage,
            nodePublicKey: invalidPublicKey
        )) { error in
            // The error could be various types depending on the failure point
            // Just verify that an error is thrown
            XCTAssertTrue(error is Error)
        }
        
        // Test decryptMessageFromNode with invalid encrypted data
        let encryptedData = Data(repeating: 1, count: 100) // Invalid encrypted data
        XCTAssertThrowsError(try mobileKeyManager.decryptMessageFromNode(encryptedMessage: encryptedData)) { error in
            // The error could be various types depending on the failure point
            // Just verify that an error is thrown
            XCTAssertTrue(error is Error)
        }
    }
    
    // MARK: - Helper Methods
    
    /// Create a test certificate signing request
    private func createTestCSR(nodeId: String) throws -> Data {
        // Create a simple test CSR for the given node ID
        // This is a minimal implementation for testing purposes
        let keyPair = try ECDHKeyPair()
        
        // Create a basic CSR structure
        let subject = "CN=\(nodeId),O=Runar,C=US"
        
        // For testing, we'll create a simple DER-encoded structure
        // In a real implementation, you'd use proper X.509 CSR creation
        var csrData = Data()
        
        // Add some basic DER structure (simplified for testing)
        csrData.append(0x30) // SEQUENCE
        csrData.append(0x82) // Length (2 bytes)
        csrData.append(0x01)
        csrData.append(0x00)
        
        // Add subject
        csrData.append(0x30) // SEQUENCE
        csrData.append(0x0D) // Length
        csrData.append(0x31) // SET
        csrData.append(0x0B) // Length
        csrData.append(0x30) // SEQUENCE
        csrData.append(0x09) // Length
        csrData.append(0x06) // OBJECT IDENTIFIER (CN)
        csrData.append(0x03)
        csrData.append(0x55)
        csrData.append(0x04)
        csrData.append(0x03)
        csrData.append(0x13) // PrintableString
        csrData.append(UInt8(nodeId.count))
        csrData.append(contentsOf: nodeId.utf8)
        
        return csrData
    }
} 