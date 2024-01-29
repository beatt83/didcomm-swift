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

/**
 A secret (private key) abstraction.
 
 - Parameters:
   - kid: The key ID identifying a secret (private key).
         Must have the same value as the key ID (`id` field)
         of the corresponding method in DID Doc containing a public key.
   - type: The secret (private key) type.
           Must have the same value as type (`type` field) of
           the corresponding method in DID Doc containing a public key.
   - verificationMaterial: The value of the secret (private key) as a string.
                           The value is type-specific and has the same format
                           as the corresponding public key value from the DID Doc.
                           For example, for 'JsonWebKey2020' type, it will be a JWK JSON string.
                           For 'X25519KeyAgreementKey2019' type, it will be a base58-encoded string.
 */
public struct Secret {
    public let kid: String
    public let type: KnownVerificationMaterialType
    public let verificationMaterial: VerificationMaterial
    
    public init(
        kid: String,
        type: KnownVerificationMaterialType,
        verificationMaterial: VerificationMaterial
    ) {
        self.kid = kid
        self.type = type
        self.verificationMaterial = verificationMaterial
    }
}

extension Secret: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(kid)
        hasher.combine(type.rawValue)
        hasher.combine(verificationMaterial.format.rawValue)
        hasher.combine(verificationMaterial.value)
    }
}

extension Secret: Equatable {
    public static func == (lhs: Secret, rhs: Secret) -> Bool {
        lhs.kid == rhs.kid &&
        lhs.type == rhs.type &&
        lhs.verificationMaterial.value == rhs.verificationMaterial.value &&
        lhs.verificationMaterial.format == rhs.verificationMaterial.format
    }
}
