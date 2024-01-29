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

struct MetadataBuilder {
    var encrypted: Bool
    var authenticated: Bool
    var nonRepudiation: Bool
    var anonymousSender: Bool
    var reWrappedInForward: Bool
    var encryptedTo: [String]?
    var encryptedFrom: String?
    var signFrom: String?
    var fromPriorIssuerKid: String?
    var encAlgAuth: AuthCryptAlg?
    var encAlgAnon: AnonCryptAlg?
    var signAlg: SignAlg?
    var signedMessage: [String: Any]?
    var fromPriorJwt: String?
    
    init(
        encrypted: Bool = false,
        authenticated: Bool = false,
        nonRepudiation: Bool = false,
        anonymousSender: Bool = false,
        reWrappedInForward: Bool = false,
        encryptedTo: [String]? = nil,
        encryptedFrom: String? = nil,
        signFrom: String? = nil,
        fromPriorIssuerKid: String? = nil,
        encAlgAuth: AuthCryptAlg? = nil,
        encAlgAnon: AnonCryptAlg? = nil,
        signAlg: SignAlg? = nil,
        signedMessage: [String: Any]? = nil,
        fromPriorJwt: String? = nil
    ) {
        self.encrypted = encrypted
        self.authenticated = authenticated
        self.nonRepudiation = nonRepudiation
        self.anonymousSender = anonymousSender
        self.reWrappedInForward = reWrappedInForward
        self.encryptedTo = encryptedTo
        self.encryptedFrom = encryptedFrom
        self.signFrom = signFrom
        self.fromPriorIssuerKid = fromPriorIssuerKid
        self.encAlgAuth = encAlgAuth
        self.encAlgAnon = encAlgAnon
        self.signAlg = signAlg
        self.signedMessage = signedMessage
        self.fromPriorJwt = fromPriorJwt
    }
    
    func toMetadata() -> Metadata {
        .init(
            encrypted: encrypted,
            authenticated: authenticated,
            nonRepudiation: nonRepudiation,
            anonymousSender: anonymousSender,
            reWrappedInForward: reWrappedInForward,
            encryptedTo: encryptedTo,
            encryptedFrom: encryptedFrom,
            signFrom: signFrom,
            fromPriorIssuerKid: fromPriorIssuerKid,
            encAlgAuth: encAlgAuth,
            encAlgAnon: encAlgAnon,
            signAlg: signAlg,
            signedMessage: signedMessage,
            fromPriorJwt: fromPriorJwt
        )
    }
}

struct EnvelopeUnpack {
    enum EnvelopType {
        case jwm
        case jws
        case jwe
    }
    
    let packedMessage: Data
    let expectDecryptByAllKeys: Bool
    let didResolver: DIDResolver
    let secretResolver: SecretResolver
    
    func unpack() async throws -> UnpackResult {
        let result = try await unpack(packedMessage: packedMessage, metadata: .init())
        
        guard let messageJson = try JSONSerialization.jsonObject(with: result.message) as? [String: Any] else {
            throw DIDCommError.somethingWentWrong
        }
        return .init(message: try Message(fromJson: messageJson), metadata: result.metadata.toMetadata())
    }
    
    func unpack(packedMessage: Data, metadata: MetadataBuilder) async throws -> (message: Data, metadata: MetadataBuilder) {
        switch getEnvelopeType(payload: packedMessage) {
        case .jwe:
            let result = try await EncryptedEnvelopeUnpack(
                packedMessage: packedMessage,
                expectDecryptByAllKeys: expectDecryptByAllKeys,
                didResolver: didResolver,
                secretResolver: secretResolver
            ).unpack(metadata: metadata)
            print(try result.message.tryToString())
            return try await unpack(packedMessage: result.message, metadata: result.metadata)
        case .jws:
            let result = try await SignedEnvelopeUnpack(
                packedMessage: packedMessage,
                expectDecryptByAllKeys: expectDecryptByAllKeys,
                didResolver: didResolver,
                secretResolver: secretResolver
            ).unpack(metadata: metadata)
            return try await unpack(packedMessage: result.message, metadata: result.metadata)
        case .jwm:
            return try await PlainEnvelopeUnpack(
                packedMessage: packedMessage,
                expectDecryptByAllKeys: expectDecryptByAllKeys,
                didResolver: didResolver,
                secretResolver: secretResolver
            ).unpack(metadata: metadata)
        }
    }
    
    private func getEnvelopeType(payload: Data) -> EnvelopType {
        if isJWE(payload: payload) {
            return .jwe
        } else if isJWS(payload: payload) {
            return .jws
        } else {
            return .jwm
        }
    }
}

private func isJWE(payload: Data) -> Bool {
    return (try? JSONDecoder().decode(DefaultJWEJson.self, from: payload)) != nil
}

private func isJWS(payload: Data) -> Bool {
    print(try? payload.tryToString())
    typealias DefaultJWSJsonFlattened = JWSJsonFlattened<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl>
    
    if (try? JSONDecoder().decode(DefaultJWSJson.self, from: payload)) != nil {
        return true
    } else if (try? JSONDecoder().decode(DefaultJWSJsonFlattened.self, from: payload)) != nil {
        return true
    } else {
        return false
    }
}
