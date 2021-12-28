// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CSAuthSample",
    platforms: [
        .macOS(.v10_15)
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
        .package(name: "SwiftyXPC", url: "https://github.com/CharlesJS/SwiftyXPC.git", from: "0.3.0"),
        .package(name: "CSCoreFoundation", url: "https://github.com/CharlesJS/CSCoreFoundation.git", from: "0.2.0")
    ],
    targets: [
        .target(
            name: "CSAuthSampleApp",
            dependencies: ["CSAuthSampleCommon", "CSAuthSampleInternal"]
        ),
        .target(
            name: "CSAuthSampleHelper",
            dependencies: ["CSAuthSampleCommon", "CSAuthSampleInternal"]
        ),
        .target(
            name: "CSAuthSampleCommon",
            dependencies: ["SwiftyXPC", "CSCoreFoundation"]
        ),
        .target(
            name: "CSAuthSampleInternal",
            dependencies: ["CSAuthSampleCommon"]
        ),
    ]
)
