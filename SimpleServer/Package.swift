// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SimpleServer",
    platforms: [.macOS(.v10_12)],
    products: [
        .executable(name: "SimpleServer", targets: ["SimpleServer"])
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(path: "..")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "SimpleServer",
            dependencies: ["PracticeTLS"],
            resources: [.copy("Cert")]),
        .testTarget(
            name: "SimpleServerTests",
            dependencies: ["SimpleServer"]),
    ]
)
