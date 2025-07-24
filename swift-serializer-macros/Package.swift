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
        .package(url: "https://github.com/swiftlang/swift-syntax.git", from: "509.0.0"),
        .package(url: "https://github.com/valpackett/SwiftCBOR.git", from: "0.4.0"),
    ],
    targets: [
        .target(
            name: "RunarSerializerMacros",
            dependencies: ["RunarSerializerMacrosMacros"]
        ),
                       .macro(
                   name: "RunarSerializerMacrosMacros",
                   dependencies: [
                       .product(name: "SwiftSyntaxMacros", package: "swift-syntax"),
                       .product(name: "SwiftCompilerPlugin", package: "swift-syntax"),
                       .product(name: "SwiftCBOR", package: "SwiftCBOR"),
                   ]
               ),
        .testTarget(
            name: "RunarSerializerMacrosTests",
            dependencies: ["RunarSerializerMacros"]
        ),
    ]
) 