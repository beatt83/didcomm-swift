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
import JSONWebAlgorithms
import JSONWebEncryption

struct Encrypter {
    static func encrypt(
        payload: Data,
        from: Key?,
        to: [Key],
        keyAlg: KeyManagementAlgorithm,
        encAlg: ContentEncryptionAlgorithm
    ) throws -> Data {
        let skid = from?.id
        let kids = to.map(\.id).sorted()
        let apu = try skid.map { try $0.tryToData() }
        let apv = try APV.calculateAPV(kids: kids)
        
        let protectedHeader = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg,
            agreementPartyUInfo: apu,
            agreementPartyVInfo: apv,
            senderKeyId: skid
        )
        
        let serialization = try JWE.jsonSerialization(
            payload: payload,
            protectedHeader: protectedHeader,
            senderKey: from?.jwk,
            recipientKeys: to.map { $0.jwk }
        )
        
        return try JSONEncoder.jose.encode(serialization)
    }
}
