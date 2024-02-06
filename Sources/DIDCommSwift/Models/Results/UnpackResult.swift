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

/// Represents the result of unpacking a DIDComm message.
///
/// Contains the unpacked message and its associated metadata, providing detailed information
/// about the security and routing aspects of the message processing.
public struct UnpackResult {
    /// The unpacked DIDComm message, ready for further processing or handling by the application.
    public let message: Message
    /// Metadata associated with the unpacked message, detailing various aspects of its security
    /// and handling during the unpacking process.
    public let metadata: Metadata
}

/// Metadata associated with an unpacked DIDComm message.
///
/// Provides insights into the security properties of the message, such as encryption,
/// authentication, non-repudiation, and anonymity of the sender, as well as information
/// about how the message was handled during unpacking.
public struct Metadata {
    /// Indicates whether the message was encrypted.
    public let encrypted: Bool
    /// Indicates whether the sender was authenticated.
    public let authenticated: Bool
    /// Indicates whether the message provides non-repudiation.
    public let nonRepudiation: Bool
    /// Indicates whether the sender of the message is anonymous.
    public let anonymousSender: Bool
    /// Indicates whether the message was re-wrapped in a forward message during routing.
    public let reWrappedInForward: Bool
    /// An array of identifiers (Key IDs, or `kids`) for the keys to which the message was encrypted, if applicable.
    public let encryptedTo: [String]?
    /// The identifier (Key ID, or `kid`) of the sender's key used for authenticated encryption, if applicable.
    public let encryptedFrom: String?
    /// The identifier (Key ID, or `kid`) of the key used to sign the message, if applicable.
    public let signFrom: String?
    /// An optional identifier for the issuer of a `fromPrior` claim, if such a claim was included in the message.
    public let fromPriorIssuerKid: String?
    /// The algorithm used for authenticated encryption, if applicable.
    public let encAlgAuth: AuthenticatedEncryptionAlg?
    /// The algorithm used for anonymous encryption, if applicable.
    public let encAlgAnon: AnonymousEncryptionAlgorithms?
    /// The algorithm used for signing the message, if applicable.
    public let signAlg: SignAlg?
    /// A dictionary representing the signed message, if the message was signed.
    public let signedMessage: [String: Any]?
    /// The JWT representing a `fromPrior` claim, if such a claim was included in the message.
    public let fromPriorJwt: String?
    
    init(
        encrypted: Bool = false,
        authenticated: Bool = false,
        nonRepudiation: Bool = false,
        anonymousSender: Bool = false,
        reWrappedInForward: Bool = false,
        encryptedTo: [String]? = nil,
        encryptedFrom: String? = nil,
        signFrom: String? = nil,
        fromPriorIssuerKid: String? = nil,
        encAlgAuth: AuthenticatedEncryptionAlg? = nil,
        encAlgAnon: AnonymousEncryptionAlgorithms? = nil,
        signAlg: SignAlg? = nil,
        signedMessage: [String: Any]? = nil,
        fromPriorJwt: String? = nil
    ) {
        self.encrypted = encrypted
        self.authenticated = authenticated
        self.nonRepudiation = nonRepudiation
        self.anonymousSender = anonymousSender
        self.reWrappedInForward = reWrappedInForward
        self.encryptedTo = encryptedTo
        self.encryptedFrom = encryptedFrom
        self.signFrom = signFrom
        self.fromPriorIssuerKid = fromPriorIssuerKid
        self.encAlgAuth = encAlgAuth
        self.encAlgAnon = encAlgAnon
        self.signAlg = signAlg
        self.signedMessage = signedMessage
        self.fromPriorJwt = fromPriorJwt
    }
}
