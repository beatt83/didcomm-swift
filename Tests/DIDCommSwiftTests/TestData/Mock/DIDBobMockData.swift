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

let bobDID = "did:example:bob"

let bobVerificationMethodKeyAgreeX25519_1 = DIDDocument.VerificationMethod(
    id: "did:example:bob#key-x25519-1",
    controller: "did:example:bob#key-x25519-1",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let bobVerificationMethodKeyAgreeX25519_2 = DIDDocument.VerificationMethod(
    id: "did:example:bob#key-x25519-2",
    controller: "did:example:bob#key-x25519-2",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let bobVerificationMethodKeyAgreeX25519_3 = DIDDocument.VerificationMethod(
    id: "did:example:bob#key-x25519-3",
    controller: "did:example:bob#key-x25519-3",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let bobVerificationMethodKeyAgreeX25519NotInSecrets_1 = DIDDocument.VerificationMethod(
    id: "did:example:bob#key-x25519-not-secrets-1",
    controller: "did:example:bob#key-x25519-not-secrets-1",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let bobVerificationMethodKeyAgreeP256_1 = DIDDocument.VerificationMethod(
    id: "did:example:bob#key-p256-1",
    controller: "did:example:bob#key-p256-1",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kid": "did:example:bob#key-p256-1",
                "kty": "EC",
                "crv": "P-256",
                "x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
                "y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let bobVerificationMethodKeyAgreeP256_2 = DIDDocument.VerificationMethod(
    id: "did:example:bob#key-p256-2",
    controller: "did:example:bob#key-p256-2",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kid": "did:example:bob#key-p256-2",
                "kty": "EC",
                "crv": "P-256",
                "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let bobVerificationMethodKeyAgreeP256NotInSecrets1 = DIDDocument.VerificationMethod(
    id: "did:example:bob#key-p256-not-secrets-1",
    controller: "did:example:bob#key-p256-not-secrets-1",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let bobVerificationMethodKeyAgreeP384_1 = DIDDocument.VerificationMethod(
    id: "did:example:bob#key-p384-1",
    controller: "did:example:bob#key-p384-1",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kty": "EC",
                "crv": "P-384",
                "x": "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
                "y": "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let bobVerificationMethodKeyAgreeP384_2 = DIDDocument.VerificationMethod(
    id: "did:example:bob#key-p384-2",
    controller: "did:example:bob#key-p384-2",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kty": "EC",
                "crv": "P-384",
                "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let bobVerificationMethodKeyAgreeP384NotInSecrets1 = DIDDocument.VerificationMethod(
    id: "did:example:bob#key-p384-not-secrets-1",
    controller: "did:example:bob#key-p384-not-secrets-1",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kty": "EC",
                "crv": "P-384",
                "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let bobVerificationMethodKeyAgreeP521_1 = DIDDocument.VerificationMethod(
    id: "did:example:bob#key-p521-1",
    controller: "did:example:bob#key-p521-1",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kty": "EC",
                "crv": "P-521",
                "x": "Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
                "y": "ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let bobVerificationMethodKeyAgreeP521_2 = DIDDocument.VerificationMethod(
    id: "did:example:bob#key-p521-2",
    controller: "did:example:bob#key-p521-2",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kty": "EC",
                "crv": "P-521",
                "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
                "y": "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let bobVerificationMethodKeyAgreeP521NotInSecrets1 = DIDDocument.VerificationMethod(
    id: "did:example:bob#key-p521-not-secrets-1",
    controller: "did:example:bob#key-p521-not-secrets-1",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
        {
            "kty": "EC",
            "crv": "P-521",
            "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
            "y": "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH"
        }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let didDocBobTestVectors = DIDDocument(
    id: "did:example:bob",
    verificationMethods: [
        bobVerificationMethodKeyAgreeX25519_1,
        bobVerificationMethodKeyAgreeX25519_2,
        bobVerificationMethodKeyAgreeX25519_3,
        bobVerificationMethodKeyAgreeP256_1,
        bobVerificationMethodKeyAgreeP256_2,
        bobVerificationMethodKeyAgreeP384_1,
        bobVerificationMethodKeyAgreeP384_2,
        bobVerificationMethodKeyAgreeP521_1,
        bobVerificationMethodKeyAgreeP521_2
    ],
    authentication: [],
    keyAgreement: [
        .stringValue("did:example:bob#key-x25519-1"),
        .stringValue("did:example:bob#key-x25519-2"),
        .stringValue("did:example:bob#key-x25519-3"),
        .stringValue("did:example:bob#key-p256-1"),
        .stringValue("did:example:bob#key-p256-2"),
        .stringValue("did:example:bob#key-p384-2"),
        .stringValue("did:example:bob#key-p521-1"),
        .stringValue("did:example:bob#key-p521-2"),
    ]
)

let didDocBobWithNoSecrets = DIDDocument(
    id: "did:example:bob",
    verificationMethods: [
        bobVerificationMethodKeyAgreeX25519_1,
        bobVerificationMethodKeyAgreeX25519_2,
        bobVerificationMethodKeyAgreeX25519_3,
        bobVerificationMethodKeyAgreeX25519NotInSecrets_1,
        bobVerificationMethodKeyAgreeP256_1,
        bobVerificationMethodKeyAgreeP256_2,
        bobVerificationMethodKeyAgreeP256NotInSecrets1,
        bobVerificationMethodKeyAgreeP384_1,
        bobVerificationMethodKeyAgreeP384_2,
        bobVerificationMethodKeyAgreeP384NotInSecrets1,
        bobVerificationMethodKeyAgreeP521_1,
        bobVerificationMethodKeyAgreeP521_2,
        bobVerificationMethodKeyAgreeP521NotInSecrets1
    ],
    authentication: [],
    keyAgreement: [
        .stringValue("did:example:bob#key-x25519-1"),
        .stringValue("did:example:bob#key-x25519-2"),
        .stringValue("did:example:bob#key-x25519-3"),
        .stringValue("did:example:bob#key-x25519-not-secrets-1"),
        .stringValue("did:example:bob#key-p256-1"),
        .stringValue("did:example:bob#key-p256-2"),
        .stringValue("did:example:bob#key-p256-not-secrets-1"),
        .stringValue("did:example:bob#key-p384-2"),
        .stringValue("did:example:bob#key-p384-not-secrets-1"),
        .stringValue("did:example:bob#key-p521-1"),
        .stringValue("did:example:bob#key-p521-2"),
        .stringValue("did:example:bob#key-p521-not-secrets-1"),
    ],
    services: [
        .init(
            id: "did:example:123456789abcdefghi#didcomm-1",
            type: "",
            serviceEndpoint: .string("http://example.com/path"),
            routingKeys: ["did:example:mediator1#key-x25519-1"],
            accept: [DIDCommProfile.v2.rawValue, DIDCommProfile.aip2_rfc587.rawValue]
        )
    ]
)
