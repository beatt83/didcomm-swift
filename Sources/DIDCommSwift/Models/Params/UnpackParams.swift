/*
 * Copyright 2024 Gonçalo Frade
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation

/// Parameters for unpacking a DIDComm message.
///
/// This structure configures the options and requirements for decrypting and verifying
/// a DIDComm message, including handling of forwarded messages and resolution of DIDs and secrets.
public struct UnpackParams {
    /// The packed DIDComm message as a string. This message is expected to be encrypted and/or signed
    /// and potentially wrapped in a forwarding message.
    public let packedMessage: String
    /// Indicates whether the message should be attempted to be decrypted with all available keys.
    /// When `false`, decryption will only be attempted with keys specified or inferred from the message.
    public let expectDecryptByAllKeys: Bool
    /// Specifies whether a message wrapped in a forwarding message should be automatically unwrapped
    /// and the inner message processed. This is relevant for messages that have been forwarded through mediators.
    public let unwrapReWrappingForward: Bool
    /// An optional `DIDResolver` for resolving DIDs mentioned in the message. If not provided, a default resolver is used.
    public let didResolver: DIDResolver?
    /// An optional `SecretResolver` for resolving secrets needed to decrypt the message. If not provided, a default resolver is used.
    public let secretResolver: SecretResolver?

    /// Initializes a new set of parameters for unpacking a DIDComm message.
    /// - Parameters:
    ///   - packedMessage: The encrypted and/or signed DIDComm message to be unpacked.
    ///   - expectDecryptByAllKeys: Optional. Specifies whether decryption should be attempted with all keys. Defaults to `false`.
    ///   - unwrapReWrappingForward: Optional. Specifies automatic unwrapping of forwarding messages. Defaults to `true`.
    ///   - didResolver: Optional. A custom DID resolver for DID resolution within the message.
    ///   - secretResolver: Optional. A custom secret resolver for decrypting the message.
    ///
    /// This initializer allows for the configuration of unpacking process, catering to various security and
    /// privacy requirements, as well as handling complex scenarios such as message forwarding and multi-key decryption.
    public init(
        packedMessage: String,
        expectDecryptByAllKeys: Bool = false,
        unwrapReWrappingForward: Bool = true,
        didResolver: DIDResolver? = nil,
        secretResolver: SecretResolver? = nil
    ) {
        self.packedMessage = packedMessage
        self.expectDecryptByAllKeys = expectDecryptByAllKeys
        self.unwrapReWrappingForward = unwrapReWrappingForward
        self.didResolver = didResolver
        self.secretResolver = secretResolver
    }
}
