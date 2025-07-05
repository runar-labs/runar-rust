// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "RunarSwift",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),
    ],
    products: [
        .library(
            name: "RunarSwift",
            targets: ["RunarSwift"]),
    ],
    dependencies: [
        // No external dependencies for now
    ],
    targets: [
        .target(
            name: "RunarSwift",
            dependencies: [],
            path: "Sources/RunarSwift",
            resources: [
                .copy("Resources/runar_ios_ffi.h"),
            ],
            cSettings: [
                .headerSearchPath("Resources"),
                .define("SWIFT_PACKAGE"),
            ],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("Foundation"),
                .linkedLibrary("runar_ios_ffi_macos", .when(platforms: [.macOS])),
                .linkedLibrary("runar_ios_ffi_ios", .when(platforms: [.iOS])),
            ]
        ),
        .testTarget(
            name: "RunarSwiftTests",
            dependencies: ["RunarSwift"],
            path: "Tests/RunarSwiftTests"),
    ]
) 