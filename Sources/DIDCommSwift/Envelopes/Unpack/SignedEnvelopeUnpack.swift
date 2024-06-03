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
import JSONWebSignature

struct SignedEnvelopeUnpack {
    let packedMessage: Data
    let expectDecryptByAllKeys: Bool
    let didResolver: DIDResolver
    let secretResolver: SecretResolver
    
    func unpack(metadata: MetadataBuilder) async throws -> (message: Data, metadata: MetadataBuilder) {
        typealias DefaultJWSJsonFlattened = JWSJsonFlattened<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl>
        
        let jwsJson = try (try? JSONDecoder().decode(DefaultJWSJson.self, from: packedMessage))
        ?? (JSONDecoder().decode(DefaultJWSJsonFlattened.self, from: packedMessage).fullJson())
        
        let keySelector = RecipientKeySelector(
            didResolver: didResolver,
            secretResolver: secretResolver
        )
        
        var metadata = metadata
        
        guard try await jwsJson.getKids().asyncFirst(where: { kid in
            guard let key = try? await keySelector.findVerificationKey(signFrom: kid) else {
                return false
            }
            let result = try JWS.verify(jwsJson: packedMessage, key: key.jwk)
            if
                result,
                let signature = try jwsJson.signatures.first(where: { try $0.getKid() == kid }),
                let algorithm = signature.protectedHeader?.algorithm ?? signature.unprotectedHeader?.algorithm
            {
                switch algorithm {
                case .ES256:
                    metadata.signAlg = .es256
                case .ES256K:
                    metadata.signAlg = .es256k
                case .ES384:
                    metadata.signAlg = .es384
                case .ES512:
                    metadata.signAlg = .es512
                case .EdDSA:
                    metadata.signAlg = .ed25519
                default:
                    break
                }
                metadata.signFrom = kid
            }
            return result
        }) != nil else {
           throw DIDCommError.somethingWentWrong
        }
        
        guard let messageJsonObj = try JSONSerialization.jsonObject(with: jwsJson.payload) as? [String: Any] else {
            throw DIDCommError.malformedMessage(try jwsJson.payload.tryToString())
        }
        
        metadata.authenticated = true
        metadata.nonRepudiation = true
        metadata.signedMessage = messageJsonObj
        
        return (message: jwsJson.payload, metadata: metadata)
    }
}

public extension Sequence {
    func asyncFirst(
        `where`: (Element) async throws -> Bool
    ) async rethrows -> Element? {
        for element in self {
            if try await `where`(element) {
                return element
            }
        }
        return nil
    }
}
