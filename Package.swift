// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "PracticeTLS",
    platforms: [.macOS(.v10_12), .iOS(.v10)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .executable(name: "server", targets: ["SimpleHTTPServer"]),
        .library(name: "PracticeTLS", targets: ["PracticeTLS"])
    ],
    dependencies: [
        .package(url: "https://github.com/robbiehanson/CocoaAsyncSocket", from: "7.6.4"),
        .package(url: "https://github.com/onevcat/Rainbow", .upToNextMajor(from: "4.0.0")),
        .package(url: "https://github.com/BinaryParadise/CryptoSwift.git", .upToNextMajor(from: "1.4.1")),
        .package(url: "https://github.com/apple/swift-nio-http2.git", from: "1.5.0"),
    ], targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(name: "SimpleHTTPServer",
                dependencies:
                    ["PracticeTLS",
                    .product(name: "NIOHTTP2", package: "swift-nio-http2")],
                resources: [.copy("Cert")]),
        .target(
            name: "PracticeTLS",
            dependencies: ["CocoaAsyncSocket", "Rainbow", "SecurityRSA", "CryptoSwift"]),
        .target(name: "SecurityRSA"),
        .testTarget(
            name: "PracticeTLSTests",
            dependencies: ["PracticeTLS"]),
    ],
    swiftLanguageVersions: [.version("5.0")]
)
