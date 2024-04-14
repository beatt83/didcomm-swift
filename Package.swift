// swift-tools-version: 5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "didcomm-swift",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .macCatalyst(.v15),
        .tvOS(.v15),
        .watchOS(.v8)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "didcomm-swift",
            targets: ["DIDCommSwift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swift-libp2p/swift-multibase.git", .upToNextMajor(from: "0.0.1")),
        .package(url: "https://github.com/beatt83/didcore-swift.git", .upToNextMinor(from: "1.1.0")),
        .package(url: "https://github.com/beatt83/jose-swift.git", .upToNextMinor(from: "2.1.0"))
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "DIDCommSwift",
            dependencies: [
                "jose-swift",
                .product(name: "Multibase", package: "swift-multibase"),
                .product(name: "DIDCore", package: "didcore-swift")
            ]
        ),
        .testTarget(
            name: "DIDCommSwiftTests",
            dependencies: [
                "DIDCommSwift",
                .product(name: "Multibase", package: "swift-multibase")
            ]),
    ]
)
