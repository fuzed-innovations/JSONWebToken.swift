// swift-tools-version:4.0

import PackageDescription


#if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
let dependencies = [
  Package.Dependency.package(url: "https://github.com/IBM-Swift/BlueRSA.git", from: "1.0.0"),
]
let excludes = ["HMAC/HMACCryptoSwift.swift"]
let targetDependencies: [Target.Dependency] = ["CryptorRSA"]
#else
let dependencies = [
  Package.Dependency.package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "0.15.0"),
  Package.Dependency.package(url: "https://github.com/IBM-Swift/BlueRSA.git", from: "1.0.0"),
]
let excludes = ["HMAC/HMACCommonCrypto.swift"]
let targetDependencies: [Target.Dependency] = ["CryptoSwift", "CryptorRSA"]
#endif


let package = Package(
  name: "JWT",
  products: [
    .library(name: "JWT", targets: ["JWT"]),
  ],
  dependencies: dependencies,
  targets: [
    .target(name: "JWA", dependencies: targetDependencies, exclude: excludes),
    .target(name: "JWT", dependencies: ["JWA"]),
    .testTarget(name: "JWATests", dependencies: ["JWA"]),
    .testTarget(name: "JWTTests", dependencies: ["JWT"]),
  ]
)
