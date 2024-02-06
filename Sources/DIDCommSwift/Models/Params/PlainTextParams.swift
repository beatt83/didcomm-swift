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

/// Parameters for packing a plaintext DIDComm message.
///
/// This structure encapsulates options and configurations needed to prepare a DIDComm message
/// in its plaintext form, which can be useful for debugging or in contexts where messages do not
/// require encryption for confidentiality or integrity.
public struct PlainTextParams {
    /// The DIDComm message to be packed.
    public let message: Message
    /// An optional identifier for the issuer of a `fromPrior` claim, if present in the message.
    public let fromPriorIssuerKid: String?
    /// Indicates whether routing information should be included in the packed message.
    public let routingEnabled: Bool
    /// An optional `DIDResolver` for resolving DIDs within the message. If not provided, a default resolver is used.
    public let didResolver: DIDResolver?
    /// An optional `SecretResolver` for resolving secrets needed by the message. If not provided, a default resolver is used.
    public let secretResolver: SecretResolver?

    /// Initializes a new set of parameters for plaintext message packing.
    /// - Parameters:
    ///   - message: The DIDComm message to pack.
    ///   - fromPriorIssuerKid: Optional. The key identifier of the issuer for a `fromPrior` claim.
    ///   - routingEnabled: Specifies whether to include routing information. Defaults to `true`.
    ///   - didResolver: Optional. A custom DID resolver. If `nil`, the default resolver will be used.
    ///   - secretResolver: Optional. A custom secret resolver. If `nil`, the default resolver will be used.
    ///
    /// This initializer allows for customization of the message packing process, enabling or disabling
    /// features like routing and providing custom resolvers for DIDs and secrets as needed.
    public init(
        message: Message,
        fromPriorIssuerKid: String? = nil,
        routingEnabled: Bool = true,
        didResolver: DIDResolver? = nil,
        secretResolver: SecretResolver? = nil
    ) {
        self.message = message
        self.fromPriorIssuerKid = fromPriorIssuerKid
        self.routingEnabled = routingEnabled
        self.didResolver = didResolver
        self.secretResolver = secretResolver
    }
}
