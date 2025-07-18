// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "RunarTransporter",
    platforms: [
        .macOS(.v11), // Updated for Network.framework QUIC support
        .iOS(.v14),   // Updated for Network.framework QUIC support
        .tvOS(.v14),  // Updated for Network.framework QUIC support
        .watchOS(.v7) // Updated for consistency
    ],
    products: [
        .library(
            name: "RunarTransporter",
            targets: ["RunarTransporter"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.6.0"),
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.25.0")
    ],
    targets: [
        .target(
            name: "RunarTransporter",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf")
            ]
        ),
        .testTarget(
            name: "RunarTransporterTests",
            dependencies: ["RunarTransporter"]
        ),
    ]
)

/*
 QUIC COMPATIBILITY ANALYSIS:
 
 Current Implementation: UDP with custom QUIC-like framing
 Rust Implementation: Quinn 0.11.x with rustls TLS
 
 COMPATIBILITY OPTIONS:
 
 1. ngtcp2 (C library with Swift bindings)
    ✅ Full QUIC protocol support
    ❌ Different TLS stack (OpenSSL vs rustls)
    ❌ Complex C bindings required
    ❌ Different certificate validation
 
 2. Apple Network.framework (CURRENTLY IMPLEMENTING)
    ✅ Native iOS/macOS integration
    ✅ Real QUIC protocol support
    ⚠️ Platform limited (iOS 14+, macOS 11+)
    ⚠️ Limited custom certificate validation
    ⚠️ Less control over QUIC configuration
 
 3. Quinn Swift Bindings (RECOMMENDED)
    ✅ Same QUIC implementation as Rust
    ✅ Same TLS stack (rustls)
    ✅ Identical certificate validation
    ✅ Full protocol compatibility
    ⚠️ Requires Quinn C API Swift bindings
 
 CURRENT STATUS: Implementing Network.framework QUIC transport
 for immediate real QUIC support while maintaining compatibility.
 */ 