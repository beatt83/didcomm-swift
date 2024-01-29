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

import Multibase
import DIDCore
import Foundation
import JSONWebKey

struct MultibasePublicKey: Key {
    let id: String
    let jwk: JSONWebKey.JWK
    let curve: String
    
    init(id: String, jwk: JSONWebKey.JWK, curve: String) {
        self.id = id
        self.jwk = jwk
        self.curve = curve
    }
    
    init(id: String, material: VerificationMaterial) throws {
        self.id = id
        guard let multibaseStr = String(data: material.value, encoding: .utf8) else {
            throw DIDCommError.invalidBase64URLKey
        }
        let multibaseDecoded = try BaseEncoding.decode(multibaseStr).data
        let multicodec = try Multicodec().fromMulticodec(value: multibaseDecoded)
        let curve: JSONWebKey.JWK.CryptographicCurve
        switch multicodec.codec {
        case .ED25519:
            curve = .ed25519
        case .X25519:
            curve = .x25519
        }
        self.jwk = .init(
            keyType: .octetKeyPair,
            keyID: id,
            curve: curve,
            x: multicodec.data
        )
        self.curve = curve.rawValue
    }
}
