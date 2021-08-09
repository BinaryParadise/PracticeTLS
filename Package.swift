// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "PracticeTLSTool",
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .executable(name: "PracticeTLSTool", targets: ["PracticeTLSTool"]),
        .library(name: "PracticeTLS", targets: ["PracticeTLS"])
    ],
    dependencies: [
        .package(url: "https://github.com/robbiehanson/CocoaAsyncSocket", from: "7.6.4"),
        .package(url: "https://github.com/onevcat/Rainbow", .upToNextMajor(from: "4.0.0")),
        .package(name: "PerfectThread", url: "https://github.com/PerfectlySoft/Perfect-Thread.git", from: "3.0.0"),
    ], targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "PracticeTLSTool",
            dependencies: ["PracticeTLS"]),
        .target(
            name: "PracticeTLS",
            dependencies: ["CocoaAsyncSocket", "Rainbow", "PerfectThread"],
            resources: [.process("localhost.cer")]),
        .testTarget(
            name: "PracticeTLSTests",
            dependencies: ["PracticeTLS"],
            resources: [.process("localhost.cer")]),
    ],
    swiftLanguageVersions: [.version("5.0")]
)
