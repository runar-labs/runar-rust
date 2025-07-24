// swift-tools-version: 6.0
import CompilerPluginSupport
import PackageDescription

let package = Package(
    name: "RunarSerializerMacros",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .tvOS(.v13),
        .watchOS(.v6)
    ],
    products: [
        .library(
            name: "RunarSerializerMacros",
            targets: ["RunarSerializerMacros"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-syntax.git", from: "509.0.0"),
    ],
    targets: [
        .macro(
            name: "RunarSerializerMacros",
            dependencies: [
                .product(name: "SwiftSyntaxMacros", package: "swift-syntax"),
                .product(name: "SwiftCompilerPlugin", package: "swift-syntax"),
            ],
            path: "Sources/RunarSerializerMacros"
        ),
        .testTarget(
            name: "RunarSerializerMacrosTests",
            dependencies: ["RunarSerializerMacros"],
            path: "Tests/RunarSerializerMacrosTests"
        ),
    ]
) 