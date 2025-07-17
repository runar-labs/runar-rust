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
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.60.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.25.0"),
        .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.6.0"),
        .package(url: "https://github.com/apple/swift-async-algorithms.git", from: "1.0.0")
        // TODO: Add Quinn Swift bindings for real QUIC compatibility
        // .package(url: "https://github.com/quinn-rs/quinn-swift.git", from: "0.1.0")
    ],
    targets: [
        .target(
            name: "RunarTransporter",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOExtras", package: "swift-nio-extras"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "AsyncAlgorithms", package: "swift-async-algorithms")
                // TODO: Add Quinn dependency
                // .product(name: "Quinn", package: "quinn-swift")
            ],
            exclude: ["QuicTransporter_old.swift.old"]
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