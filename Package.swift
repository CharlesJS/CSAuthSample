// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CSAuthSample",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "CSAuthSampleApp",
            targets: ["CSAuthSampleApp"]
        ),
        .library(
            name: "CSAuthSampleHelper",
            targets: ["CSAuthSampleHelper"]
        ),
        .library(
            name: "CSAuthSampleCommon",
            targets: ["CSAuthSampleCommon"]
        ),
    ],
    dependencies: [
        .package(name: "SwiftyXPC", url: "https://github.com/CharlesJS/SwiftyXPC.git", from: "0.2.6-beta")
    ],
    targets: [
        .target(
            name: "CSAuthSampleApp",
            dependencies: ["CSAuthSampleCommon"]
        ),
        .target(
            name: "CSAuthSampleHelper",
            dependencies: ["CSAuthSampleCommon"]
        ),
        .target(
            name: "CSAuthSampleCommon",
            dependencies: ["SwiftyXPC"]
        ),
    ]
)
