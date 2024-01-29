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

@testable import DIDCommSwift
import DIDCore
import Foundation

class AliceSecretResolverMock: SecretResolver {
    let secrets: [Secret] = [
        Secret(
            kid: "did:example:alice#key-1",
            type: .authentication(.jsonWebKey2020),
            verificationMaterial: VerificationMaterial(
                format: .jwk,
                value: """
                    {
                       "kty":"OKP",
                       "d":"pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
                       "crv":"Ed25519",
                       "x":"G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
                    }
                """.data(using: .utf8)!
            )
        ),
        Secret(
            kid: "did:example:alice#key-2",
            type: .authentication(.jsonWebKey2020),
            verificationMaterial: VerificationMaterial(
                format: .jwk,
                value: """
                    {
                       "kty":"EC",
                       "d":"7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A",
                       "crv":"P-256",
                       "x":"2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                       "y":"BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
                    }
                """.data(using: .utf8)!
            )
        ),
        Secret(
            kid: "did:example:alice#key-3",
            type: .authentication(.jsonWebKey2020),
            verificationMaterial: VerificationMaterial(
                format: .jwk,
                value: """
                    {
                       "kty":"EC",
                       "d":"N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA",
                       "crv":"secp256k1",
                       "x":"aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
                       "y":"JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
                    }
                """.data(using: .utf8)!
            )
        ),
        Secret(
            kid: "did:example:alice#key-x25519-1",
            type: .authentication(.jsonWebKey2020),
            verificationMaterial: VerificationMaterial(
                format: .jwk,
                value: """
                    {
                       "kty":"OKP",
                       "d":"r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA",
                       "crv":"X25519",
                       "x":"avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
                    }
                """.data(using: .utf8)!
            )
        ),
        Secret(
            kid: "did:example:alice#key-p256-1",
            type: .authentication(.jsonWebKey2020),
            verificationMaterial: VerificationMaterial(
                format: .jwk,
                value: """
                    {
                       "kty":"EC",
                       "d":"sB0bYtpaXyp-h17dDpMx91N3Du1AdN4z1FUq02GbmLw",
                       "crv":"P-256",
                       "x":"L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
                       "y":"SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
                    }
                """.data(using: .utf8)!
            )
        ),
        Secret(
            kid: "did:example:alice#key-p521-1",
            type: .authentication(.jsonWebKey2020),
            verificationMaterial: VerificationMaterial(
                format: .jwk,
                value: """
                    {
                       "kty":"EC",
                       "d":"AQCQKE7rZpxPnX9RgjXxeywrAMp1fJsyFe4cir1gWj-8t8xWaM_E2qBkTTzyjbRBu-JPXHe_auT850iYmE34SkWi",
                       "crv":"P-521",
                       "x":"AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
                       "y":"AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk"
                    }
                """.data(using: .utf8)!
            )
        )
    ]
    
    lazy var secretResolver = SecretResolverInMemory(secrets: secrets)
    
    func findKey(kid: String) async throws -> Secret? {
        try await secretResolver.findKey(kid: kid)
    }
    
    func findKeys(kids: Set<String>) async throws -> Set<String> {
        try await secretResolver.findKeys(kids: kids)
    }
}
