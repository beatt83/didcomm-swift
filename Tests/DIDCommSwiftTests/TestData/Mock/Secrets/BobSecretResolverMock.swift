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

class BobSecretResolverMock: SecretResolver {
    let secrets: [Secret] = [
        Secret(kid: "did:example:bob#key-x25519-1",
              type: .authentication(.jsonWebKey2020),
              verificationMaterial: VerificationMaterial(format: .jwk, value: """
                {
                   "kty":"OKP",
                   "d":"b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0",
                   "crv":"X25519",
                   "x":"GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E"
                }
                """.data(using: .utf8)!)),
        
        Secret(kid: "did:example:bob#key-x25519-2",
              type: .authentication(.jsonWebKey2020),
              verificationMaterial: VerificationMaterial(format: .jwk, value: """
                {
                   "kty":"OKP",
                   "d":"p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk",
                   "crv":"X25519",
                   "x":"UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
                }
                """.data(using: .utf8)!)),

        Secret(kid: "did:example:bob#key-x25519-3",
              type: .authentication(.jsonWebKey2020),
              verificationMaterial: VerificationMaterial(format: .jwk, value: """
                {
                   "kty":"OKP",
                   "d":"f9WJeuQXEItkGM8shN4dqFr5fLQLBasHnWZ-8dPaSo0",
                   "crv":"X25519",
                   "x":"82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY"
                }
                """.data(using: .utf8)!)),
        
        Secret(kid: "did:example:bob#key-p256-1",
              type: .authentication(.jsonWebKey2020),
              verificationMaterial: VerificationMaterial(format: .jwk, value: """
                {
                   "kty":"EC",
                   "d":"PgwHnlXxt8pwR6OCTUwwWx-P51BiLkFZyqHzquKddXQ",
                   "crv":"P-256",
                   "x":"FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
                   "y":"6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY"
                }
                """.data(using: .utf8)!)),
        
        Secret(kid: "did:example:bob#key-p256-2",
              type: .authentication(.jsonWebKey2020),
              verificationMaterial: VerificationMaterial(format: .jwk, value: """
                {
                   "kty":"EC",
                   "d":"agKz7HS8mIwqO40Q2dwm_Zi70IdYFtonN5sZecQoxYU",
                   "crv":"P-256",
                   "x":"n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                   "y":"ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw"
                }
                """.data(using: .utf8)!)),
        
        Secret(kid: "did:example:bob#key-p384-1",
              type: .authentication(.jsonWebKey2020),
              verificationMaterial: VerificationMaterial(format: .jwk, value: """
                {
                   "kty":"EC",
                   "d":"ajqcWbYA0UDBKfAhkSkeiVjMMt8l-5rcknvEv9t_Os6M8s-HisdywvNCX4CGd_xY",
                   "crv":"P-384",
                   "x":"MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
                   "y":"X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7"
                }
                """.data(using: .utf8)!)),
        
        Secret(kid: "did:example:bob#key-p384-2",
              type: .authentication(.jsonWebKey2020),
              verificationMaterial: VerificationMaterial(format: .jwk, value: """
                {
                   "kty":"EC",
                   "d":"OiwhRotK188BtbQy0XBO8PljSKYI6CCD-nE_ZUzK7o81tk3imDOuQ-jrSWaIkI-T",
                   "crv":"P-384",
                   "x":"2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                   "y":"W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd"
                }
                """.data(using: .utf8)!)),

        Secret(kid: "did:example:bob#key-p521-1",
              type: .authentication(.jsonWebKey2020),
              verificationMaterial: VerificationMaterial(format: .jwk, value: """
                {
                   "kty":"EC",
                   "d":"AV5ocjvy7PkPgNrSuvCxtG70NMj6iTabvvjSLbsdd8OdI9HlXYlFR7RdBbgLUTruvaIRhjEAE9gNTH6rWUIdfuj6",
                   "crv":"P-521",
                   "x":"Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
                   "y":"ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH"
                }
                """.data(using: .utf8)!)),

        Secret(kid: "did:example:bob#key-p521-2",
              type: .authentication(.jsonWebKey2020),
              verificationMaterial: VerificationMaterial(format: .jwk, value: """
                {
                   "kty":"EC",
                   "d":"ABixMEZHsyT7SRw-lY5HxdNOofTZLlwBHwPEJ3spEMC2sWN1RZQylZuvoyOBGJnPxg4-H_iVhNWf_OtgYODrYhCk",
                   "crv":"P-521",
                   "x":"ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
                   "y":"AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH"
                }
                """.data(using: .utf8)!
            ))
    ]
    
    lazy var secretResolver = SecretResolverInMemory(secrets: secrets)
    
    func findKey(kid: String) async throws -> Secret? {
        try await secretResolver.findKey(kid: kid)
    }
    
    func findKeys(kids: Set<String>) async throws -> Set<String> {
        try await secretResolver.findKeys(kids: kids)
    }
}
