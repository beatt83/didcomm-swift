# DIDCommV2 Swift Package

DIDCommV2 is a comprehensive Swift package designed to facilitate the development of applications utilizing Decentralized Identity Communication (DIDComm) V2 protocol. It offers Swift developers a robust toolkit for building secure, private communication systems based on decentralized identities.

[![Swift](https://img.shields.io/badge/swift-brightgreen.svg)]() [![iOS](https://img.shields.io/badge/ios-brightgreen.svg)]() [![MacOS](https://img.shields.io/badge/macos-brightgreen.svg)]() [![WatchOS](https://img.shields.io/badge/watchos-brightgreen.svg)]() [![TvOS](https://img.shields.io/badge/tvos-brightgreen.svg)]()

## Installation

### Swift Package Manager (SPM)

To integrate `DIDCore` into your Xcode project using SPM, specify it in your `Package.swift`:

```swift
dependencies: [
    .package(url: "git@github.com:beatt83/didcore-swift.git", .upToNextMajor(from: "0.1.0"))
]
```

## Features

- **DIDComm V2 Protocol Support:** Implements the DIDComm V2 protocol for secure, private messaging based on decentralized identities.
- **Message Encryption and Decryption:** Offers tools for encrypting and decrypting messages, ensuring privacy and security in communications.
- **DID-Based Authentication:** Leverages decentralized identifiers for authentication purposes in messaging applications.
- **Flexible API:** Designed with a developer-friendly API, making it easy to integrate DIDComm V2 functionalities into Swift applications.

## Usage

```swift
import DIDCommSwift

// The DIDDocument includes structures for VerificationMethod, Service, ServiceEndpoint, and so on.
let didcomm = DIDComm(
    didResolver: // DID resolver instance,
    secretResolver: // Secret Resolver Instance
)

let packed = try await didcomm.packEncrypted(params: .init(
    message: ... // Message,
    to: ... // to DID,
    from: ... // from DID,
    encAlgAuth: .a256CbcHs512Ecdh1puA256kw
))

let unpacked = try await didcomm.unpack(
    params: .init(packedMessage: packed.packedMessage)
)
```

## References

- [DIDComm Messaging Specification](https://identity.foundation/didcomm-messaging/spec/)
- [DIDComm V2 Protocol Guide](https://didcomm.org/book/v2/)

## Contributing

We highly appreciate community contributions. To contribute, please fork the repository, push your changes, and open a pull request.

## License

This project is licensed under the Apache 2.0 License.
