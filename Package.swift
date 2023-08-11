// swift-tools-version: 5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "didcomm-swift",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "didcomm-swift",
            targets: ["didcomm-swift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/proxyco/swift-jose.git", .upToNextMinor(from: "0.1.0"))
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "didcomm-swift"),
        .testTarget(
            name: "didcomm-swiftTests",
            dependencies: ["didcomm-swift"]),
    ]
)
