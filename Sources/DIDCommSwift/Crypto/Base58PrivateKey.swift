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

import DIDCore
import Foundation
import JSONWebKey
import Base64

struct Base58PrivateKey: Key {
    let id: String
    let jwk: JSONWebKey.JWK
    let curve: String
    
    init(id: String, jwk: JSONWebKey.JWK, curve: String) {
        self.id = id
        self.jwk = jwk
        self.curve = curve
    }
    
    init(id: String, curve: String, material: VerificationMaterial) throws {
        self.id = id
        let rawKey = try material.decodedKey()
        guard rawKey.count == 64 else {
            throw DIDCommError.invalidKeySize(64)
        }
        self.jwk = .init(
            keyType: .octetKeyPair,
            keyID: id,
            curve: .init(rawValue: curve),
            x: rawKey[0..<32],
            d: rawKey[32..<64]
        )
        self.curve = curve
    }
}
