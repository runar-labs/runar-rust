// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "RunarSerializer",
    platforms: [
        .iOS(.v13),
        .macOS(.v12),
        .tvOS(.v13),
        .watchOS(.v6)
    ],
    products: [
        .library(
            name: "RunarSerializer",
            targets: ["RunarSerializer"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/valpackett/SwiftCBOR.git", from: "0.4.0"),
        .package(path: "../swift-serializer-macros"),
        .package(path: "../swift-keys"),
    ],
    targets: [
        .target(
            name: "RunarSerializer",
            dependencies: [
                "SwiftCBOR",
                .product(name: "RunarSerializerMacros", package: "swift-serializer-macros"),
                .product(name: "RunarKeys", package: "swift-keys")
            ],
            path: "Sources/RunarSerializer"
        ),
        .testTarget(
            name: "RunarSerializerTests",
            dependencies: [
                "RunarSerializer",
                .product(name: "RunarSerializerMacros", package: "swift-serializer-macros"),
                "SwiftCBOR"
            ],
            path: "Tests/RunarSerializerTests"
        ),
    ]
) 