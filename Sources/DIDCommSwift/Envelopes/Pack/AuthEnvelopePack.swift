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
import JSONWebKey

struct AuthEnvelopePack {
    let message: Message
    let from: String
    let to: [String]
    let algorithm: AuthenticatedEncryptionAlg
    let protectedSender: AnonymousEncryptionAlgorithms?
    let fromPriorIssuerKid: String?
    let routingEnabled: Bool
    let signFrom: String?
    
    let didResolver: DIDResolver
    let secretResolver: SecretResolver
    
    func pack() async throws -> EncryptedResult {
        let keySelector = SenderKeySelector(didResolver: didResolver, secretResolver: secretResolver)
        
        let (fromKey, recipientKeys) = try await keySelector.findAuthCryptKeys(from: from, to: to)
        
        let (message, fromPriorIssuerKid) = try await FromPrior.packFromPrior(
            message: message,
            fromPriorIssuerKid: fromPriorIssuerKid,
            keySelector: keySelector
        )
        
        let messageJsonStr = try message.didcommJson()
        
        let (payload, signFromKid) = try await signIfNeeded(
            message: messageJsonStr,
            keySelector: keySelector
        )
        
        let (jweEnc, jweAlg) = algorithm.jweReference
        
        let encryptedMessage = try Encrypter.encrypt(
            payload: payload,
            from: fromKey,
            to: recipientKeys,
            keyAlg: jweAlg,
            encAlg: jweEnc
        )
        
        let protectedIfNedded = try protectSenderIfNeeded(
            message: encryptedMessage,
            recipientKeys: recipientKeys
        )
        
        let messageJson = try protectedIfNedded.tryToString()
        
        let routingResult: RoutingResult?
        if routingEnabled {
            routingResult = try await Routing(
                didResolver: didResolver,
                secretResolver: secretResolver
            ).packRouting(
                to: to,
                packedMessage: messageJson
            )
        } else {
            routingResult = nil
        }
        
        return .init(
            packedMessage: messageJson,
            toKids: recipientKeys.map(\.id),
            fromKid: fromKey.id,
            signFromKid: signFromKid,
            fromPriorIssuerKid: fromPriorIssuerKid,
            routingResult: routingResult
        )
    }
    
    private func signIfNeeded(
        message: Data,
        keySelector: SenderKeySelector
    ) async throws -> (message: Data, id: String?) {
        guard let signFrom = signFrom else {
            return (message, nil)
        }
        let key = try await keySelector.findSigningKey(signFrom: signFrom)
        let signature = try Signer.sign(payload: message, key: key)
        return (message, key.id)
    }
    
    private func protectSenderIfNeeded(
        message: Data,
        recipientKeys: [Key]
    ) throws -> Data {
        guard let protectedSender else {
            return message
        }
        let (jweEnc, jweAlg) = protectedSender.jweReference
        
        return try Encrypter.encrypt(
            payload: message,
            from: nil,
            to: recipientKeys,
            keyAlg: jweAlg,
            encAlg: jweEnc
        )
    }
}
