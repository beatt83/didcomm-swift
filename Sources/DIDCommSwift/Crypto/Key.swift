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

protocol Key {
    var id: String { get }
    var jwk: JSONWebKey.JWK { get }
    var curve: String { get }
}

struct KeyHelper {
    static func fromSecret(_ secret: Secret) throws -> Key {
        switch secret.type {
        case .agreement(.jsonWebKey2020), .authentication(.jsonWebKey2020):
            guard secret.verificationMaterial.format == .jwk else {
                throw DIDCommError.invalidSecretFormatForMethodType(
                    methodType: secret.type.rawValue,
                    format: secret.verificationMaterial.format.rawValue,
                    expected: VerificationMaterialFormat.jwk.rawValue
                )
            }
            return try JsonWebKey(id: secret.kid, materialValue: secret.verificationMaterial.value)
        case .agreement(.x25519KeyAgreementKey2019), .authentication(.ed25519VerificationKey2018):
            guard secret.verificationMaterial.format == .base58 else {
                throw DIDCommError.invalidSecretFormatForMethodType(
                    methodType: secret.type.rawValue,
                    format: secret.verificationMaterial.format.rawValue,
                    expected: VerificationMaterialFormat.base58.rawValue
                )
            }
            return try Base58PrivateKey(
                id: secret.kid,
                curve: try secret.type.getCurve(),
                material: secret.verificationMaterial
            )
        case .agreement(.x25519KeyAgreementKey2020), .authentication(.ed25519VerificationKey2020):
            guard secret.verificationMaterial.format == .multibase else {
                throw DIDCommError.invalidSecretFormatForMethodType(
                    methodType: secret.type.rawValue,
                    format: secret.verificationMaterial.format.rawValue,
                    expected: VerificationMaterialFormat.multibase.rawValue
                )
            }
            return try MultibasePrivateKey(
                id: secret.kid,
                material: secret.verificationMaterial
            )
        default:
            throw DIDCommError.unsupportedKey("", supported: ["Ed25519", "X25519"])
        }
    }
    
    static func fromVerificationMethod(method: DIDDocument.VerificationMethod) throws -> Key {
        guard let type = KnownVerificationMaterialType(rawValue: method.type) else {
            throw DIDCommError.invalidBase64URLKey
        }
        switch type {
        case .agreement(.jsonWebKey2020), .authentication(.jsonWebKey2020):
            guard method.material.format == .jwk else {
                throw DIDCommError.invalidSecretFormatForMethodType(
                    methodType: method.material.format.rawValue,
                    format: type.rawValue,
                    expected: VerificationMaterialFormat.jwk.rawValue
                )
            }
            return try JsonWebKey(id: method.id, materialValue: method.material.value)
            
        case .agreement(.x25519KeyAgreementKey2019), .authentication(.ed25519VerificationKey2018):
            guard method.material.format == .base58 else {
                throw DIDCommError.invalidSecretFormatForMethodType(
                    methodType: method.material.format.rawValue,
                    format: type.rawValue,
                    expected: VerificationMaterialFormat.base58.rawValue
                )
            }
            let curve: String = type == .agreement(.x25519KeyAgreementKey2019) ? "X25519" : "Ed25519"
            return try Base58PublicKey(id: method.id, curve: curve, material: method.material)
            
        case .agreement(.x25519KeyAgreementKey2020), .authentication(.ed25519VerificationKey2020):
            guard method.material.format == .multibase else {
                throw DIDCommError.invalidSecretFormatForMethodType(
                    methodType: method.material.format.rawValue,
                    format: type.rawValue,
                    expected: VerificationMaterialFormat.multibase.rawValue
                )
            }
            return try MultibasePublicKey(id: method.id, material: method.material)
            
        default:
            throw DIDCommError.unsupportedVerificationMethodTypeException(method.type)
        }
    }
}

private extension KnownVerificationMaterialType {
    func getCurve() throws -> String {
        switch self {
        case .agreement(.x25519KeyAgreementKey2019), .agreement(.x25519KeyAgreementKey2020):
            return "X25519"
        case .authentication(.ed25519VerificationKey2018), .authentication(.ed25519VerificationKey2020):
            return "Ed25519"
        default:
            throw DIDCommError.unsupportedKey("", supported: ["X25519", "ED25519"])
        }
    }
}
