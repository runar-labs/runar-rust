// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "RunarSerializer",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
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
    ],
    targets: [
        .target(
            name: "RunarSerializer",
            dependencies: [
                "SwiftCBOR",
                .product(name: "RunarSerializerMacros", package: "swift-serializer-macros")
            ],
            path: "Sources/RunarSerializer"
        ),
        .testTarget(
            name: "RunarSerializerTests",
            dependencies: [
                "RunarSerializer",
                .product(name: "RunarSerializerMacros", package: "swift-serializer-macros")
            ],
            path: "Tests/RunarSerializerTests"
        ),
    ]
) 