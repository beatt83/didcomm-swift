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
import JSONWebSignature
import JSONWebAlgorithms

struct Signer {
    static func sign(payload: Data, key: Key) throws -> String {
        let alg = try getJWSAlgorithm(jwk: key.jwk)
        let protectedHeader = DefaultJWSHeaderImpl(
            algorithm: .init(rawValue: alg.rawValue),
            type: Typ.signed.rawValue
        )
        let header = DefaultJWSHeaderImpl(keyID: key.id)
        let signedJWS: Data = try JWS.jsonSerialization(
            payload: payload,
            protectedHeader: protectedHeader,
            unprotectedHeader: header,
            keys: [key.jwk]
        )
        
        return try signedJWS.tryToString()
    }
}

private func getJWSAlgorithm(jwk: JSONWebKey.JWK) throws -> JSONWebAlgorithms.SigningAlgorithm {
    switch jwk.keyType {
    case .ellipticCurve:
        switch jwk.curve {
        case .p256:
            return .ES256
        case .secp256k1:
            return .ES256K
        default:
            // TODO: Switch by error that curve is unsupported
            throw DIDCommError.somethingWentWrong
        }
    case .octetKeyPair:
        switch jwk.curve {
        case .ed25519:
            return .EdDSA
        default:
            // TODO: Switch by error that curve is unsupported
            throw DIDCommError.somethingWentWrong
        }
    default:
        // TODO: Switch by error that kty is unsupported
        throw DIDCommError.somethingWentWrong
    }
}

private func getJWSKeyData(jwk: JSONWebKey.JWK) throws -> Data {
    switch jwk.keyType {
    case .ellipticCurve:
        switch jwk.curve {
        case .p256:
            guard
                let privateKeyB64 = jwk.d,
                let privateKeyData = Data(base64URLEncoded: privateKeyB64)
            else { throw DIDCommError.somethingWentWrong }
            return privateKeyData
        case .secp256k1:
            guard
                let privateKeyB64 = jwk.d,
                let privateKeyData = Data(base64URLEncoded: privateKeyB64)
            else { throw DIDCommError.somethingWentWrong }
            return privateKeyData
        default:
            // TODO: Switch by error that curve is unsupported
            throw DIDCommError.somethingWentWrong
        }
    case .octetKeyPair:
        switch jwk.curve {
        case .ed25519:
            guard
                let privateKeyB64 = jwk.d,
                let privateKeyData = Data(base64URLEncoded: privateKeyB64)
            else { throw DIDCommError.somethingWentWrong }
            return privateKeyData
        default:
            // TODO: Switch by error that curve is unsupported
            throw DIDCommError.somethingWentWrong
        }
    default:
        // TODO: Switch by error that kty is unsupported
        throw DIDCommError.somethingWentWrong
    }
}
