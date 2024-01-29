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

public struct DIDComm {
    public let didResolver: DIDResolver
    public let secretResolver: SecretResolver
    
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
    ///   - params: Pack Plaintext Parameters.
    /// - Throws: DIDCommException if pack cannot be done, in particular:
    ///   - DIDDocException if a DID or DID URL (for example a key ID) cannot be resolved to a DID Doc.
    ///   - SecretNotFoundException if there is no secret for the given DID or DID URL (key ID)
    ///   - DIDCommIllegalArgumentException if invalid input is provided.
    ///
    /// - Returns: Result of Pack Plaintext Operation.
    public func packPlainText(params: PlainTextParams) async throws -> PlainTextResult {
        let didResolver = params.didResolver ?? self.didResolver
        let secretResolver = params.secretResolver ?? self.secretResolver
        
        let result = try await PlainEnvelopePack(
            message: params.message,
            fromPriorIssuerKid: params.fromPriorIssuerKid,
            didResolver: didResolver,
            secretResolver: secretResolver
        ).pack()
        
        return PlainTextResult(
            packedMessage: result.packedMessage,
            fromPriorIssuerKid: result.fromPriorIssuerKid
        )
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
    ///   - params: Pack Signed Parameters.
    /// - Throws: DIDCommException if pack cannot be done, in particular:
    ///   - DIDDocException if a DID or DID URL (for example a key ID) cannot be resolved to a DID Doc.
    ///   - SecretNotFoundException if there is no secret for the given DID or DID URL (key ID)
    ///   - DIDCommIllegalArgumentException if invalid input is provided.
    ///
    /// - Returns: Result of Pack Signed Operation.
    public func packSigned(params: SignedParams) async throws -> SignedResult {
        let didResolver = params.didResolver ?? self.didResolver
        let secretResolver = params.secretResolver ?? self.secretResolver
       
        let result = try await SignedEnvelopePack(
            message: params.message,
            signFrom: params.signFrom,
            fromPriorIssuerKid: params.fromPriorIssuerKid,
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
    ///   - params: Pack Encrypted Parameters.
    /// - Throws: DIDCommException if pack cannot be done, in particular:
    ///   - DIDDocException if a DID or DID URL (for example a key ID) cannot be resolved to a DID Doc.
    ///   - SecretNotFoundException if there is no secret for the given DID or DID URL (key ID)
    ///   - DIDCommIllegalArgumentException if invalid input is provided.
    ///   - IncompatibleCryptoException if the sender and target crypto is not compatible (for example, there are no compatible keys for key agreement)
    ///
    /// - Returns: Result of pack encrypted operation.
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
                signFrom: params.signFrom,
                didResolver: didResolver,
                secretResolver: secretResolver
            ).pack()
        } else {
            throw DIDCommError.somethingWentWrong
        }

        return EncryptedResult(
            packedMessage: result.packedMessage,
            toKids: result.toKids,
            fromKid: result.fromKid,
            signFromKid: result.signFromKid,
            fromPriorIssuerKid: result.fromPriorIssuerKid,
            serviceMetadata: nil
        )
    }

    /// Unpacks the packed DIDComm message by doing decryption and verifying the signatures.
    ///
    /// - Parameters:
    ///   - params: Unpack Parameters.
    /// - Throws: DIDCommException if unpack cannot be done, in particular:
    ///   - MalformedMessageException if the message is invalid (cannot be decrypted, signature is invalid, the plaintext is invalid, etc.)
    ///   - DIDDocException if a DID or DID URL (for example a key ID) cannot be resolved to a DID Doc.
    ///   - SecretNotFoundException if there is no secret for the given DID or DID URL (key ID)
    ///
    /// - Returns: Result of Unpack Operation.
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

    // NOTE: There might be more functions or implementations to convert but they were not provided in the original request. The above translations are based on the provided Kotlin code.

}
