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
import JSONWebToken
import JSONWebSignature

struct FromPrior {
    
    static func packFromPrior(message: Message, fromPriorIssuerKid: String?, keySelector: SenderKeySelector) async throws -> (Message, String?) {
        if let fromPrior = message.fromPrior, let fromPriorIssuerKid = fromPriorIssuerKid ?? fromPrior.iss {
            let key = try await keySelector.findSigningKey(signFrom: fromPriorIssuerKid)
            let updatedMessage = message.updateFromPrior(
                fromPrior: nil,
                jwt: try signJWT(claims: DefaultJWTClaimsImpl(fromPrior: fromPrior), key: key)
            )
            return (updatedMessage, key.id)
        }
        return (message, nil)
    }

    static func unpackFromPrior(
        message: Message,
        keySelector: RecipientKeySelector
    ) async throws -> (Message, String?) {
        guard
            let fromPriorJwt = message.fromPriorJwt,
            let issKid = try extractFromPriorKid(fromPriorJwt: fromPriorJwt)
        else { return (message, nil) }
        let key = try await keySelector.findVerificationKey(signFrom: issKid)
        let jwt = try JWT.verify(jwtString: fromPriorJwt, senderKey: key.jwk)
        let payload: DefaultJWTClaimsImpl = try JWT.getPayload(jwtString: fromPriorJwt)
        let newFromPrior = Message.FromPrior(
            iss: payload.iss,
            sub: payload.sub,
            aud: payload.aud?.first,
            exp: payload.exp,
            nbf: payload.nbf,
            iat: payload.iat,
            jti: payload.jti
        )
        
        let updatedMessage = message
            .updateFromPrior(fromPrior: newFromPrior, jwt: nil)
        return (updatedMessage, key.id)
    }
    
    private static func signJWT(claims: DefaultJWTClaimsImpl, key: Key) throws -> String {
        let signingAlgorithm = try key.jwk.signingAlgorithm()
        return try JWT.signed(
            payload: claims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: signingAlgorithm, keyID: key.id),
            key: key.jwk
        ).jwtString
    }
}

private func extractFromPriorKid(fromPriorJwt: String) throws -> String? {
    let segments = fromPriorJwt.split(separator: ".")
    guard
        segments.count == 3,
        let jsonData = Data(base64URLEncoded: String(segments[0]))
    else { throw DIDCommError.malformedMessage(fromPriorJwt) }
    let jwsHeader = try JSONDecoder().decode(DefaultJWSHeaderImpl.self, from: jsonData)
    return jwsHeader.keyID
}

extension DefaultJWTClaimsImpl {
    init(fromPrior: Message.FromPrior) {
        self.init(
            iss: fromPrior.iss,
            sub: fromPrior.sub,
            aud: fromPrior.aud.map { [$0] },
            exp: fromPrior.exp,
            nbf: fromPrior.nbf,
            iat: fromPrior.iat,
            jti: fromPrior.jti
        )
    }
}
