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

/// Represents the result of signing a DIDComm message.
///
/// This structure contains the signed message along with metadata about the signing process,
/// including the identifier of the signing key, optional information about the issuer of a `fromPrior`
/// claim, and routing results if the message was processed for delivery through mediators.
public struct SignedResult {
    /// The signed message packaged as a string. This message includes the signature, providing
    /// non-repudiation and integrity verification but not confidentiality, as it is not encrypted.
    public let packedMessage: String
    /// The identifier (Key ID, or `kid`) of the key used to sign the message. This can be used
    /// to verify the signature against the signer's public key.
    public let signFromKid: String
    /// An optional identifier for the issuer of a `fromPrior` claim, if such a claim was included
    /// in the message. This is relevant for asserting identity continuity or permissions across messages.
    public let fromPriorIssuerKid: String?
    /// Optional routing results, detailing how the message has been processed for routing through
    /// mediators to reach its final destination. This is important for understanding the path
    /// a message takes through a network of mediators.
    public let routingResult: RoutingResult?
    
    init(
        packedMessage: String,
        signFromKid: String,
        fromPriorIssuerKid: String? = nil,
        routingResult: RoutingResult? = nil
    ) {
        self.packedMessage = packedMessage
        self.signFromKid = signFromKid
        self.fromPriorIssuerKid = fromPriorIssuerKid
        self.routingResult = routingResult
    }
}
