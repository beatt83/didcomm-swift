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

/// Represents the result of packing a DIDComm message into its plaintext form.
///
/// This structure contains the packed plaintext message, along with optional information about
/// the issuer of a `fromPrior` claim and any routing results if the message was processed
/// for routing through mediators.
public struct PlainTextResult {
    /// The packed plaintext message, ready for transmission or storage.
    /// This message is in a non-encrypted form and should be used carefully, considering
    /// the confidentiality and integrity requirements of the communication context.
    public let packedMessage: String
    /// An optional identifier for the issuer of a `fromPrior` claim, if such a claim was included
    /// in the message. This can be used to maintain continuity or assert identity across messages.
    public let fromPriorIssuerKid: String?
    /// Optional routing results, providing details on how the message has been processed for routing
    /// through mediators to reach its intended recipient(s). This is relevant in scenarios where
    /// the message needs to be forwarded through one or more intermediaries.
    public let routingResults: RoutingResult?
    
    init(
        packedMessage: String,
        fromPriorIssuerKid: String? = nil,
        routingResults: RoutingResult? = nil
    ) {
        self.packedMessage = packedMessage
        self.fromPriorIssuerKid = fromPriorIssuerKid
        self.routingResults = routingResults
    }
}
