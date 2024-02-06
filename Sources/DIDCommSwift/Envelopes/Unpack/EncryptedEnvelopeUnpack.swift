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
import JSONWebSignature

struct EncryptedEnvelopeUnpack {
    let packedMessage: Data
    let expectDecryptByAllKeys: Bool
    let didResolver: DIDResolver
    let secretResolver: SecretResolver
    
    func unpack(metadata: MetadataBuilder) async throws -> (message: Data, metadata: MetadataBuilder) {
        let keySelector = RecipientKeySelector(
            didResolver: didResolver,
            secretResolver: secretResolver
        )
        
        let jweJson = try JSONDecoder().decode(DefaultJWEJson.self, from: packedMessage)
        
        if let senderKid = jweJson.protected?.senderKeyID {
            guard let apu = jweJson.protected?.agreementPartyUInfo,
                try apu.tryToString() == senderKid
            else {
                throw DIDCommError.malformedMessage("APU is different of senderKid")
            }
        }
        
        let recipients = jweJson.getKids()
        
        if let skid = try jweJson.protected?.senderKeyID
            ?? jweJson.protected?.agreementPartyUInfo?.tryToString()
        {
            let (from, to) = try await keySelector.findAuthCryptKeys(from: skid, to: recipients)
            guard let recipientKey = to.first?.jwk else {
                throw DIDCommError.secretsNotFound(recipients)
            }
            let decrypted = try JWE.decrypt(jweJson: packedMessage, senderKey: from.jwk, recipientKey: recipientKey)
            
            var metadata = metadata
            metadata.encryptedTo = recipients
            metadata.encryptedFrom = skid
            metadata.encrypted = true
            metadata.authenticated = true
            if 
                let keyAlg = jweJson.protected?.keyManagementAlgorithm,
                let encAlg = jweJson.protected?.encodingAlgorithm
            {
                metadata.encAlgAuth = try AuthenticatedEncryptionAlg.fromReference(keyAlg: keyAlg, encAlg: encAlg)
            }
            
            return (message: decrypted, metadata: metadata)
        } else {
            let recipientsKeys = try await keySelector.findAnonCryptKeys(to: recipients)
            guard let recipientKey = recipientsKeys.first?.jwk else {
                throw DIDCommError.secretsNotFound(recipients)
            }
            let decrypted = try JWE.decrypt(jweJson: packedMessage, recipientKey: recipientKey)
            
            var metadata = metadata
            metadata.encryptedTo = recipients
            metadata.encrypted = true
            metadata.anonymousSender = true
            
            if
                let keyAlg = jweJson.protected?.keyManagementAlgorithm,
                let encAlg = jweJson.protected?.encodingAlgorithm
            {
                metadata.encAlgAnon = try AnonymousEncryptionAlgorithms.fromReference(keyAlg: keyAlg, encAlg: encAlg)
            }
            
            return (message: decrypted, metadata: metadata)
        }
    }
}
