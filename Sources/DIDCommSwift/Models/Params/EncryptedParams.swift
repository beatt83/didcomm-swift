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

/// Parameters for encrypting a DIDComm message.
///
/// This structure configures how a DIDComm message should be encrypted, including details about the recipients,
/// encryption algorithms, and options for routing and sender protection.
public struct EncryptedParams {
    /// The DIDComm message to be encrypted.
    public let message: Message
    /// An array of recipient identifiers (DIDs) to whom the message is encrypted.
    public let to: [String]
    /// An optional identifier (DID) from which the message is sent. Used for authenticated encryption.
    public let from: String?
    /// An optional identifier (DID or key ID) for signing the message.
    public let signFrom: String?
    /// An optional identifier for the issuer of a `fromPrior` claim, if applicable.
    public let fromPriorIssuerKid: String?
    /// Indicates whether routing information should be included in the encrypted message.
    public let routingEnabled: Bool
    /// An optional algorithm for authenticated encryption, indicating the encryption should include sender authentication.
    public let encAlgAuth: AuthenticatedEncryptionAlg?
    /// An optional algorithm for anonymous encryption, not revealing the sender's identity.
    public let encAlgAnon: AnonymousEncryptionAlgorithms?
    /// Specifies whether to protect the sender's identity. When true, uses anonymous encryption.
    public let protectSenderId: Bool
    /// Indicates whether the message should be forwarded. This is relevant for mediator services.
    public let forward: Bool
    /// Optional headers to include when forwarding the message through a mediator.
    public let forwardHeaders: [String: String]?
    /// An optional service identifier for forwarding the message. Specifies a particular service endpoint for routing.
    public let forwardServiceId: String?
    /// An optional `DIDResolver` for resolving DIDs within the message. If not provided, a default resolver is used.
    public let didResolver: DIDResolver?
    /// An optional `SecretResolver` for resolving secrets needed for encryption. If not provided, a default resolver is used.
    public let secretResolver: SecretResolver?

    /// Initializes a new set of parameters for encrypting a DIDComm message.
    /// - Parameters:
    ///   - message: The DIDComm message to be encrypted.
    ///   - to: Recipient identifiers to whom the message will be encrypted.
    ///   - from: Optional. The sender identifier for authenticated encryption.
    ///   - signFrom: Optional. The identifier for signing the message.
    ///   - fromPriorIssuerKid: Optional. The key identifier of the issuer for a `fromPrior` claim.
    ///   - routingEnabled: Specifies whether to include routing information. Defaults to `true`.
    ///   - encAlgAuth: Optional. The algorithm for authenticated encryption.
    ///   - encAlgAnon: Optional. The algorithm for anonymous encryption.
    ///   - protectSenderId: Specifies whether the sender's identity should be protected. Defaults to `false`.
    ///   - forward: Specifies whether the message should be forwarded through a mediator. Defaults to `true`.
    ///   - forwardHeaders: Optional. Headers for forwarding the message.
    ///   - forwardServiceId: Optional. A service endpoint identifier for message routing.
    ///   - didResolver: Optional. A custom DID resolver for DID resolution within the message.
    ///   - secretResolver: Optional. A custom secret resolver for encryption.
    ///
    /// This initializer allows for comprehensive configuration of the message encryption process, catering to various
    /// privacy, security, and routing needs within DIDComm messaging protocols.
    public init(
        message: Message,
        to: [String],
        from: String? = nil,
        signFrom: String? = nil,
        fromPriorIssuerKid: String? = nil,
        routingEnabled: Bool = true,
        encAlgAuth: AuthenticatedEncryptionAlg? = nil,
        encAlgAnon: AnonymousEncryptionAlgorithms? = nil,
        protectSenderId: Bool = false,
        forward: Bool = true,
        forwardHeaders: [String: String]? = nil,
        forwardServiceId: String? = nil,
        didResolver: DIDResolver? = nil,
        secretResolver: SecretResolver? = nil
    ) {
        self.message = message
        self.to = to
        self.from = from
        self.signFrom = signFrom
        self.fromPriorIssuerKid = fromPriorIssuerKid
        self.routingEnabled = routingEnabled
        self.encAlgAuth = encAlgAuth
        self.encAlgAnon = encAlgAnon
        self.protectSenderId = protectSenderId
        self.forward = forward
        self.forwardHeaders = forwardHeaders
        self.forwardServiceId = forwardServiceId
        self.didResolver = didResolver
        self.secretResolver = secretResolver
    }
}
