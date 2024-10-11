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

let aliceDID = "did:example:alice"

let aliceVerificationMethodKeyAgreemX25519NotInSecret = DIDDocument.VerificationMethod(
    id: "did:example:alice#key-x25519-not-in-secrets-1",
    controller: "did:example:alice#key-x25519-not-in-secrets-1",
    type: "JsonWebKey2020",
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
            }
        """.data(using: .utf8)!
    )
)

let aliceVerificationMethodKeyAgreeX25519 = DIDDocument.VerificationMethod(
    id: "did:example:alice#key-x25519-1",
    controller: "did:example:alice#key-x25519-1",
    type: "JsonWebKey2020",
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
               "kid":"did:example:alice#key-x25519-1",
               "kty":"OKP",
               "d":"r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA",
               "crv":"X25519",
               "x":"avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
            }
        """.data(using: .utf8)!
    )
)

let aliceVerificationMethodKeyAgreeP256 = DIDDocument.VerificationMethod(
    id: "did:example:alice#key-p256-1",
    controller: "did:example:alice#key-p256-1",
    type: "JsonWebKey2020",
    material: VerificationMaterial(
        format: .jwk,
        value: Data("""
            {
                "kid":"did:example:alice#key-p256-1",
                "kty": "EC",
                "crv": "P-256",
                "d": "sB0bYtpaXyp-h17dDpMx91N3Du1AdN4z1FUq02GbmLw",
                "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
                "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
            }
        """.utf8)
    )
)

let aliceVerificationMethodKeyAgreeP521 = DIDDocument.VerificationMethod(
    id: "did:example:alice#key-p521-1",
    controller: "did:example:alice#key-p521-1",
    type: "JsonWebKey2020",
    material: VerificationMaterial(
        format: .jwk,
        value: Data("""
            {
                "kty": "EC",
                "crv": "P-521",
                "x": "Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfc7ltYl6VO5BEEP2_Z_t8EYFi2eTHbNf5Wvyqhc3deha6PeOJY",
                "y": "ATZVigRQ7UdGsQ9j-omcHVZIq8yjts8TnhTdz1fQQRI2ZHDs_SU5aF_W4oySqFPjJbRcUigw2e2_DrtXi3K_R4-u"
            }
        """.utf8)
    )
)

let aliceAuthMethod25519NotInSecret = DIDDocument.VerificationMethod(
    id: "did:example:alice#key-1",
    controller: "did:example:alice#key-1",
    type: "JsonWebKey2020",
    material: VerificationMaterial(
        format: .jwk,
        value: Data("""
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11AGj5EDya8UpR3LKkF2Zm2QUd9D5KUR2GFxedcgLdxZ"
            }
        """.utf8)
    )
)

let aliceAuthMethod25519 = DIDDocument.VerificationMethod(
    id: "did:example:alice#key-1",
    controller: "did:example:alice#key-1",
    type: "JsonWebKey2020",
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
            }
        """.data(using: .utf8)!
    )
)

let aliceAuthMethodP256 = DIDDocument.VerificationMethod(
    id: "did:example:alice#key-2",
    controller: "did:example:alice#key-2",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kid":"did:example:alice#key-2",
                "kty": "EC",
                "crv": "P-256",
                "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let aliceAuthMethodSecp256k1 = DIDDocument.VerificationMethod(
    id: "did:example:alice#key-3",
    controller: "did:example:alice#key-3",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
            {
                "kty": "EC",
                "crv": "secp256k1",
                "d": "N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA",
                "x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
                "y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
            }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

//let aliceServiceEndpoint = AnyCodable(dictionaryLiteral:
//                                        ("uri", "http://didcomm.com"),
//                                        ("accept", [String]()),
//                                        ("routing_keys", ["did:example:alice#key-x25519-1"])
//                                    )

let aliceServiceRoutingKeysDic = [
    "id": "service1",
    "type": "DIDCommMessaging",
    "serviceEndpoint": [
        "uri": "http://didcomm.com",
        "accept": [String](),
        "routing_keys": ["did:example:alice#key-x25519-1"]
    ]
] as! [String: Any]

let aliceServiceRoutingKeys = AnyCodable(aliceServiceRoutingKeysDic)

let didDocAliceSpecTestVectors = DIDDocument(
    id: "did:example:alice",
    verificationMethod: [
        aliceVerificationMethodKeyAgreeX25519,
        aliceVerificationMethodKeyAgreeP256,
        aliceVerificationMethodKeyAgreeP521,
        aliceAuthMethod25519,
        aliceAuthMethodP256,
        aliceAuthMethodSecp256k1
    ],
    authentication: [
        .stringValue("did:example:alice#key-1"),
        .stringValue("did:example:alice#key-2"),
        .stringValue("did:example:alice#key-3")
    ],
    keyAgreement: [
        .stringValue("did:example:alice#key-x25519-not-in-secrets-1"),
        .stringValue("did:example:alice#key-x25519-1"),
        .stringValue("did:example:alice#key-p256-1"),
        .stringValue("did:example:alice#key-p521-1")
    ]
)

let didDocAliceSpecWithNoSecrets = DIDDocument(
    id: "did:example:alice",
    verificationMethod: [
        aliceVerificationMethodKeyAgreemX25519NotInSecret,
        aliceVerificationMethodKeyAgreeX25519,
        aliceVerificationMethodKeyAgreeP256,
        aliceVerificationMethodKeyAgreeP521,
        aliceAuthMethod25519NotInSecret
    ],
    authentication: [
        .stringValue("did:example:alice#key-not-in-secrets-1"),
        .stringValue("did:example:alice#key-1"),
        .stringValue("did:example:alice#key-2"),
        .stringValue("did:example:alice#key-3")
    ],
    keyAgreement: [
        .stringValue("did:example:alice#key-x25519-not-in-secrets-1"),
        .stringValue("did:example:alice#key-x25519-1"),
        .stringValue("did:example:alice#key-p256-1"),
        .stringValue("did:example:alice#key-p521-1")
    ]
)

let didDocAliceSpecRoutingTestVectors = DIDDocument(
    id: "did:example:alice",
    verificationMethod: [
        aliceVerificationMethodKeyAgreeX25519,
        aliceVerificationMethodKeyAgreeP256,
        aliceVerificationMethodKeyAgreeP521,
        aliceAuthMethod25519,
    ],
    authentication: [
        .stringValue("did:example:alice#key-1"),
    ],
    keyAgreement: [
        .stringValue("did:example:alice#key-x25519-1"),
    ],
    services: [aliceServiceRoutingKeys]
)
