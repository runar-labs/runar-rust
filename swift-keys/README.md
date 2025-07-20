# Runar Keys Swift

A comprehensive certificate management system for the Runar network, implemented in Swift for iOS and macOS.

## Overview

Runar Keys Swift is the Swift implementation of the `runar-keys` Rust crate, providing a robust, standards-compliant certificate management system. It leverages Apple's native cryptographic frameworks to deliver high performance and security while maintaining full compatibility with the Rust implementation.

## Features

- **Standard X.509 Certificates**: Full compliance with PKI standards
- **Unified Cryptography**: Single ECDSA P-256 algorithm throughout
- **Proper CA Hierarchy**: Mobile CA signs all node certificates
- **QUIC Compatibility**: Certificates work seamlessly with QUIC transport
- **Production Quality**: Comprehensive validation and error handling
- **Hardware Acceleration**: Automatic Secure Enclave integration when available
- **Keychain Integration**: Secure storage using Apple's Keychain Services

## Architecture

```
Mobile User CA (Self-signed root)
└── Node TLS Certificate (signed by Mobile CA)
    └── Used for all QUIC/TLS operations
```

## Technology Stack

### Apple Native Frameworks

- **Security.framework**: ECDSA operations, key generation, certificate handling
- **CryptoKit**: Modern cryptographic operations, key derivation, symmetric encryption
- **Network.framework**: QUIC/TLS integration
- **Foundation**: Serialization, encoding, data handling

### Key Advantages

- Hardware acceleration via Secure Enclave (when available)
- Optimized for iOS/macOS performance
- Built-in certificate validation and PKI support
- Native integration with Keychain Services
- Automatic memory management and security

## Core Components

### Mobile Key Manager

Acts as a Certificate Authority for issuing node certificates and managing user keys.

```swift
let mobileManager = try MobileKeyManager(logger: logger)

// Initialize user root key
let publicKey = try mobileManager.initializeUserRootKey()

// Process node certificate request
let certMessage = try mobileManager.processSetupToken(setupToken)

// Generate network keys
let networkId = try mobileManager.generateNetworkDataKey()
```

### Node Key Manager

Generates certificate signing requests and manages received certificates.

```swift
let nodeManager = try NodeKeyManager(logger: logger)

// Generate certificate signing request
let setupToken = try nodeManager.generateCSR()

// Install received certificate
try nodeManager.installCertificate(certMessage)

// Get QUIC certificate configuration
let quicConfig = try nodeManager.getQuicCertificateConfig()
```

### Certificate Authority

Handles certificate signing and validation operations.

```swift
let ca = try CertificateAuthority(subject: "CN=Runar User CA,O=Runar,C=US")

// Sign certificate request
let certificate = try ca.signCertificateRequest(csrData: csrData, validityDays: 365)

// Get CA certificate
let caCert = ca.caCertificate
```

## Installation

### Requirements

- iOS 13.0+ / macOS 10.15+
- Xcode 12.0+
- Swift 5.3+

### Swift Package Manager

Add the following to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/your-org/runar-keys-swift.git", from: "1.0.0")
]
```

Or add it to your Xcode project:

1. File → Add Package Dependencies
2. Enter the repository URL
3. Select the version you want to use

### CocoaPods

Add to your `Podfile`:

```ruby
pod 'RunarKeys', '~> 1.0'
```

## Usage

### Basic Setup

```swift
import RunarKeys

// Create logger
let logger = Logger()

// Initialize mobile key manager
let mobileManager = try MobileKeyManager(logger: logger)

// Initialize node key manager
let nodeManager = try NodeKeyManager(logger: logger)
```

### Certificate Workflow

```swift
// 1. Node generates CSR
let setupToken = try nodeManager.generateCSR()

// 2. Mobile processes CSR and issues certificate
let certMessage = try mobileManager.processSetupToken(setupToken)

// 3. Node installs certificate
try nodeManager.installCertificate(certMessage)

// 4. Node can now use certificates for QUIC transport
let quicConfig = try nodeManager.getQuicCertificateConfig()
```

### Envelope Encryption

```swift
// Encrypt data with envelope encryption
let envelopeData = try mobileManager.encryptWithEnvelope(
    data: messageData,
    networkId: "my-network",
    profileIds: ["profile1", "profile2"]
)

// Decrypt envelope data
let decryptedData = try nodeManager.decryptEnvelopeData(envelopeData)
```

### Key Management

```swift
// Generate user profile key
let profileKey = try mobileManager.deriveUserProfileKey(label: "personal")

// Generate network data key
let networkId = try mobileManager.generateNetworkDataKey()

// Encrypt for specific profile
let encryptedData = try mobileManager.encryptForProfile(data: messageData, profileId: "personal")
```

## Security Features

### Cryptographic Validation

- Full signature verification using ECDSA P-256
- Certificate chain validation against trusted CA
- Proper X.509v3 extension validation
- Time-based validity checking

### PKI Security Model

- Mobile device acts as trusted root CA
- All node certificates must be signed by Mobile CA
- CSR-based certificate issuance ensures key ownership
- Standard cryptographic implementations (Security.framework)

### Network Security

- Separate network keys for different network contexts
- Encrypted key distribution from Mobile to nodes
- Peer certificate validation during QUIC handshake

## Performance

### Hardware Acceleration

- **Secure Enclave**: Automatically used when available for key operations
- **CryptoKit**: Optimized for Apple Silicon and Intel processors
- **Keychain Services**: Hardware-backed secure storage

### Memory Management

- **ARC**: Automatic memory management for cryptographic objects
- **Zeroing**: Automatic zeroing of sensitive data when objects are deallocated
- **Secure Enclave**: Keys never leave secure hardware when possible

## Testing

### Unit Tests

```bash
# Run unit tests
swift test

# Run with specific test case
swift test --filter MobileKeyManagerTests
```

### Integration Tests

```bash
# Run integration tests
swift test --filter EndToEndTests
```

## Compatibility

### Data Format Compatibility

- **DER encoding**: Identical certificate and key formats
- **Message serialization**: Compatible protobuf/JSON formats
- **Key representations**: Same ECDSA P-256 key formats
- **Certificate chains**: Identical X.509 certificate structures

### API Compatibility

- **Method signatures**: Similar public APIs where possible
- **Error types**: Compatible error handling patterns
- **Configuration**: Similar configuration options
- **Integration points**: Compatible with existing Rust infrastructure

## Error Handling

The library provides comprehensive error handling with detailed error messages:

```swift
do {
    let certificate = try ca.signCertificateRequest(csrData: csrData, validityDays: 365)
} catch KeyError.certificateError(let message) {
    print("Certificate error: \(message)")
} catch KeyError.validationError(let message) {
    print("Validation error: \(message)")
} catch {
    print("Unexpected error: \(error)")
}
```

## Logging

The library uses a configurable logging system:

```swift
// Create logger with custom configuration
let logger = Logger(level: .debug, subsystem: "com.runar.keys")

// Logger will output structured logs for debugging and monitoring
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/runar-keys-swift.git
cd runar-keys-swift

# Open in Xcode
open Package.swift

# Run tests
swift test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Documentation

For detailed API documentation, see the [SPECIFICATION.md](SPECIFICATION.md) file.

## Support

- **Issues**: [GitHub Issues](https://github.com/your-org/runar-keys-swift/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/runar-keys-swift/discussions)
- **Documentation**: [SPECIFICATION.md](SPECIFICATION.md)

## Roadmap

### Phase 1: Core Infrastructure ✅
- [x] Basic ECDSA P-256 operations
- [x] Certificate generation and validation
- [x] Key derivation and management
- [x] Error handling framework

### Phase 2: Mobile Key Manager 🔄
- [ ] Certificate Authority implementation
- [ ] User root key management
- [ ] Profile key derivation
- [ ] Network key management

### Phase 3: Node Key Manager 📋
- [ ] CSR generation
- [ ] Certificate installation
- [ ] QUIC certificate configuration
- [ ] Peer validation

### Phase 4: Envelope Encryption 📋
- [ ] Symmetric encryption operations
- [ ] Envelope encryption/decryption
- [ ] Key distribution mechanisms
- [ ] Cross-platform compatibility

### Phase 5: Integration and Testing 📋
- [ ] QUIC/TLS integration
- [ ] End-to-end testing
- [ ] Performance optimization
- [ ] Security auditing 