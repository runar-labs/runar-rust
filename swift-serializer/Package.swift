// swift-tools-version: 5.9
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
    ],
    targets: [
        .target(
            name: "RunarSerializer",
            dependencies: ["SwiftCBOR"],
            path: "Sources/RunarSerializer"
        ),
        .testTarget(
            name: "RunarSerializerTests",
            dependencies: ["RunarSerializer"],
            path: "Tests/RunarSerializerTests"
        ),
    ]
) 