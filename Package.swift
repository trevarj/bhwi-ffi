// swift-tools-version: 5.10

import PackageDescription

let package = Package(
  name: "Bhwi",
  platforms: [.iOS(.v16)],
  products: [
    .library(name: "Bhwi", targets: ["Bhwi"])
  ],
  targets: [
    .binaryTarget(
      name: "BhwiFFI",
      path: "target/ios/BhwiFFI.xcframework"
    ),
    .target(
      name: "Bhwi",
      dependencies: ["BhwiFFI"],
      path: "ios/Sources/Bhwi"
    ),
    .testTarget(
      name: "BhwiTests",
      dependencies: ["Bhwi"],
      path: "ios/Tests/BhwiTests",
      resources: [.process("Fixtures")]
    ),
  ]
)
