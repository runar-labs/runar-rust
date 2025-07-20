// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "RunarKeys",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .watchOS(.v8),
        .tvOS(.v15)
    ],
    products: [
        .library(
            name: "RunarKeys",
            targets: ["RunarKeys"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", .upToNextMajor(from: "1.0.0"))
    ],
    targets: [
        .target(
            name: "RunarKeys",
            dependencies: [
                .product(name: "X509", package: "swift-certificates")
            ]),
        .testTarget(
            name: "RunarKeysTests",
            dependencies: ["RunarKeys"]),
        .testTarget(
            name: "RunarKeysIntegrationTests",
            dependencies: ["RunarKeys"]),
    ]
) 