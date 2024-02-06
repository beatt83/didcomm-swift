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

/// Parameters for creating a signed DIDComm message.
///
/// This structure configures the necessary information for signing a DIDComm message, ensuring non-repudiation
/// while keeping the message unencrypted. It is used when the origin of plaintext needs to be provable to third parties
/// or when the sender cannot be authenticated to the recipient through encrypted means.
public struct SignedParams {
    /// The DIDComm message to be signed.
    public let message: Message
    /// The DID or key identifier from which the message will be signed.
    public let signFrom: String
    /// An optional identifier for the issuer of a `fromPrior` claim, if applicable.
    public let fromPriorIssuerKid: String?
    /// Indicates whether routing information should be included in the signed message.
    public let routingEnabled: Bool
    /// An optional `DIDResolver` for resolving DIDs within the message. If not provided, a default resolver is used.
    public let didResolver: DIDResolver?
    /// An optional `SecretResolver` for resolving the signing key and other secrets. If not provided, a default resolver is used.
    public let secretResolver: SecretResolver?

    /// Initializes a new set of parameters for signing a DIDComm message.
    /// - Parameters:
    ///   - message: The DIDComm message to be signed.
    ///   - signFrom: The identifier (DID or key ID) from which the message will be signed.
    ///   - fromPriorIssuerKid: Optional. The key identifier of the issuer for a `fromPrior` claim.
    ///   - routingEnabled: Specifies whether to include routing information. Defaults to `true`.
    ///   - didResolver: Optional. A custom DID resolver for DID resolution within the message.
    ///   - secretResolver: Optional. A custom secret resolver for resolving the necessary signing key.
    ///
    /// This initializer allows for comprehensive configuration of the message signing process, including the selection
    /// of the signing identity and the optional inclusion of routing information and custom resolvers.
    public init(
        message: Message,
        signFrom: String,
        fromPriorIssuerKid: String? = nil,
        routingEnabled: Bool = true,
        didResolver: DIDResolver? = nil,
        secretResolver: SecretResolver? = nil
    ) {
        self.message = message
        self.signFrom = signFrom
        self.fromPriorIssuerKid = fromPriorIssuerKid
        self.routingEnabled = routingEnabled
        self.didResolver = didResolver
        self.secretResolver = secretResolver
    }
}
