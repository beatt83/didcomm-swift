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
import JSONWebEncryption

/// A structure that facilitates DIDComm messaging by providing methods for packing and unpacking DIDComm messages.
/// It utilizes `DIDResolver` and `SecretResolver` for resolving DIDs and secrets necessary for message processing.
public struct DIDComm {
    /// Resolves DIDs to their corresponding DID Documents.
    public let didResolver: DIDResolver
    /// Resolves secrets associated with DIDs, necessary for encryption and signing.
    public let secretResolver: SecretResolver
    
    /// Initializes a new DIDComm instance with specified resolvers.
    /// - Parameters:
    ///   - didResolver: A `DIDResolver` instance for resolving DIDs.
    ///   - secretResolver: A `SecretResolver` instance for resolving secrets.
    public init(didResolver: DIDResolver, secretResolver: SecretResolver) {
        self.didResolver = didResolver
        self.secretResolver = secretResolver
        JWE.encryptionModule = .defaultWithMasterEphemeralKey
    }
    
    /// Produces [DIDComm Plaintext Messages](https://identity.foundation/didcomm-messaging/spec/#didcomm-plaintext-messages).
    ///
    /// A DIDComm message in its plaintext form that
    ///  - is not packaged into any protective envelope;
    ///  - lacks confidentiality and integrity guarantees;
    ///  - repudiable.
    ///
    /// They are therefore not normally transported across security boundaries.
    /// However, this may be a helpful format to inspect in debuggers, since it exposes underlying semantics,
    /// and it is the format used in the DIDComm spec to give examples of headers and other internals.
    /// Depending on ambient security, plaintext may or may not be an appropriate format for DIDComm data at rest.
    ///
    /// - Parameters:
    ///   - params: Parameters for packing the plaintext message, including the message itself and optional resolvers.
    /// - Throws: Various exceptions if the message cannot be packed, including resolution and input validation errors.
    /// - Returns: A `PlainTextResult` containing the packed message.
    public func packPlainText(params: PlainTextParams) async throws -> PlainTextResult {
        let didResolver = params.didResolver ?? self.didResolver
        let secretResolver = params.secretResolver ?? self.secretResolver
        
        return try await PlainEnvelopePack(
            message: params.message,
            fromPriorIssuerKid: params.fromPriorIssuerKid, 
            routingEnabled: params.routingEnabled,
            didResolver: didResolver,
            secretResolver: secretResolver
        ).pack()
    }

    /// Produces [DIDComm Signed Message](https://identity.foundation/didcomm-messaging/spec/#didcomm-signed-message).
    ///
    /// The method signs (non-repudiation added) the message keeping it unencrypted.
    /// Signed messages are only necessary when:
    ///  - the origin of plaintext must be provable to third parties;
    ///  - or the sender can’t be proven to the recipient by authenticated encryption because the recipient
    ///    is not known in advance (e.g., in a broadcast scenario).
    ///
    /// Adding a signature when one is not needed can degrade rather than enhance security because it
    /// relinquishes the sender’s ability to speak off the record.
    ///
    /// - Parameters:
    ///   - params: Parameters for packing the signed message, including the message, signer information, and optional resolvers.
    /// - Throws: Various exceptions if the message cannot be packed, including resolution and input validation errors.
    /// - Returns: A `SignedResult` containing the signed message.
    public func packSigned(params: SignedParams) async throws -> SignedResult {
        let didResolver = params.didResolver ?? self.didResolver
        let secretResolver = params.secretResolver ?? self.secretResolver
       
        let result = try await SignedEnvelopePack(
            message: params.message,
            signFrom: params.signFrom,
            fromPriorIssuerKid: params.fromPriorIssuerKid,
            routingEnabled: params.routingEnabled,
            didResolver: didResolver,
            secretResolver: secretResolver
        ).pack()

        return SignedResult(
            packedMessage: result.packedMessage,
            signFromKid: result.signFromKid,
            fromPriorIssuerKid: result.fromPriorIssuerKid
        )
    }

    /// Produces [DIDComm Encrypted Message](https://identity.foundation/didcomm-messaging/spec/#didcomm-encrypted-message).
    /// The method encrypts and optionally authenticates the message to the given recipient.
    ///
    /// A DIDComm encrypted message is an encrypted JWM (JSON Web Messages) that:
    ///  - hides its content from all but authorized recipients;
    ///  - (optionally) discloses and proves the sender to only those recipients;
    ///  - provides message integrity guarantees.
    ///
    /// It is important in privacy-preserving routing.
    ///
    /// - Parameters:
    ///   - params: Parameters for the encryption process, including message, recipient, and algorithm details.
    /// - Throws: Exceptions if encryption cannot be completed, including resolution, compatibility, and input validation errors.
    /// - Returns: An `EncryptedResult` containing the encrypted message.
    public func packEncrypted(params: EncryptedParams) async throws -> EncryptedResult {
        let didResolver = params.didResolver ?? self.didResolver
        let secretResolver = params.secretResolver ?? self.secretResolver
        
        let result: EncryptedResult
        if let from = params.from, let alg = params.encAlgAuth {
            result = try await AuthEnvelopePack(
                message: params.message,
                from: from,
                to: params.to,
                algorithm: alg, 
                protectedSender: params.encAlgAnon,
                fromPriorIssuerKid: params.fromPriorIssuerKid,
                routingEnabled: params.routingEnabled,
                signFrom: params.signFrom,
                didResolver: didResolver,
                secretResolver: secretResolver
            ).pack()
        } else if let alg = params.encAlgAnon {
            result = try await AnonEnvelopePack(
                message: params.message,
                to: params.to,
                algorithm: alg,
                fromPriorIssuerKid: params.fromPriorIssuerKid,
                routingEnabled: params.routingEnabled,
                signFrom: params.signFrom,
                didResolver: didResolver,
                secretResolver: secretResolver
            ).pack()
        } else {
            throw DIDCommError.unsupportedParams(required: ["encAlgAnon", "encAlgAuth", "from"])
        }

        return EncryptedResult(
            packedMessage: result.packedMessage,
            toKids: result.toKids,
            fromKid: result.fromKid,
            signFromKid: result.signFromKid,
            fromPriorIssuerKid: result.fromPriorIssuerKid,
            routingResult: result.routingResult
        )
    }

    /// Unpacks the packed DIDComm message by doing decryption and verifying the signatures.
    ///
    /// - Parameters:
    ///   - params: Parameters for the unpacking process, including the packed message and optional resolvers.
    /// - Throws: Exceptions if the message cannot be unpacked, including decryption and signature verification errors.
    /// - Returns: An `UnpackResult` with the unpacked message and metadata.
    public func unpack(params: UnpackParams) async throws -> UnpackResult {
        let didResolver = params.didResolver ?? self.didResolver
        let secretResolver = params.secretResolver ?? self.secretResolver
        
        return try await EnvelopeUnpack(
            packedMessage: params.packedMessage.tryToData(),
            expectDecryptByAllKeys: params.expectDecryptByAllKeys,
            didResolver: didResolver,
            secretResolver: secretResolver
        ).unpack()
    }
}
