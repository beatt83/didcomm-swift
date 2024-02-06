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

/// Represents the result of encrypting a DIDComm message.
///
/// This structure contains the encrypted message along with metadata about the encryption process,
/// such as the identifiers of the recipient keys, the sender key, and optional information about
/// the issuer of a `fromPrior` claim. It also includes routing results if the message was processed
/// for delivery through mediators.
public struct EncryptedResult {
    /// The encrypted DIDComm message as a string. This message ensures confidentiality, integrity,
    /// and optional sender authentication, depending on the encryption and signing methods used.
    public let packedMessage: String
    /// An array of identifiers (Key IDs, or `kids`) for the keys of the intended recipients. These
    /// identifiers can be used to determine which keys were meant to decrypt the message.
    public let toKids: [String]
    /// An optional identifier (Key ID, or `kid`) for the sender's key. This is relevant for authenticated
    /// encryption where the identity of the sender is disclosed to the recipients.
    public let fromKid: String?
    /// An optional identifier for the key used to sign the message, providing non-repudiation.
    /// This is separate from `fromKid` and is used only when the message is both signed and encrypted.
    public let signFromKid: String?
    /// An optional identifier for the issuer of a `fromPrior` claim, if such a claim was included in the message.
    /// This is used for asserting identity continuity or permissions across messages.
    public let fromPriorIssuerKid: String?
    /// Optional routing results, detailing how the message has been processed for routing through
    /// mediators to its final destination. This is critical for tracing the delivery path of the message
    /// in complex routing scenarios.
    public let routingResult: RoutingResult?
    
    init(
        packedMessage: String,
        toKids: [String],
        fromKid: String? = nil,
        signFromKid: String? = nil,
        fromPriorIssuerKid: String? = nil,
        routingResult: RoutingResult? = nil
    ) {
        self.packedMessage = packedMessage
        self.toKids = toKids
        self.fromKid = fromKid
        self.signFromKid = signFromKid
        self.fromPriorIssuerKid = fromPriorIssuerKid
        self.routingResult = routingResult
    }
}
