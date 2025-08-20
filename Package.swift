// swift-tools-version: 5.9.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "didcomm-swift",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
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
        .package(url: "https://github.com/beatt83/didcore-swift.git", .upToNextMinor(from: "2.0.1")),
        .package(url: "https://github.com/beatt83/jose-swift.git", .upToNextMajor(from: "6.0.0"))
    ],
    targets: [
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
