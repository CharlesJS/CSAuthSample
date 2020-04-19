// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CSAuthSample",
    platforms: [
        .macOS(.v10_10)
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
        )
    ],
    dependencies: [],
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
            dependencies: []
        )
    ]
)
