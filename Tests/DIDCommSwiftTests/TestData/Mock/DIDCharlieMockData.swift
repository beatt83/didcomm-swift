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

let charlieDID = "did:example:charlie"

let charlieVerificationMethodKeyAgreeX255191 = DIDDocument.VerificationMethod(
    id: "did:example:charlie#key-x25519-1",
    controller: "did:example:charlie#key-x25519-1",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
        {
            "kty": "OKP",
            "crv": "X25519",
            "x": "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
        }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let charlieVerificationMethodKeyAgreeX255192 = DIDDocument.VerificationMethod(
    id: "did:example:charlie#key-x25519-2",
    controller: "did:example:charlie#key-x25519-2",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
        {
            "kty":"OKP",
            "crv":"X25519",
            "x":"nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
        }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let charlieVerificationMethodKeyAgreeX255193 = DIDDocument.VerificationMethod(
    id: "did:example:charlie#key-x25519-3",
    controller: "did:example:charlie#key-x25519-3",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
        {
            "kty":"OKP",
            "crv":"X25519",
            "x":"nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
        }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let charlieAuthMethod25519 = DIDDocument.VerificationMethod(
    id: "did:example:charlie#key-1",
    controller: "did:example:charlie#key-1",
    type: KnownVerificationMaterialType.AuthenticationType.jsonWebKey2020.rawValue,
    material: VerificationMaterial(
        format: .jwk,
        value: """
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE"
        }
        """.data(using: .utf8)! // converting the string to Data type
    )
)

let didDocCharlie = DIDDocument(
    id: "did:example:charlie",
    verificationMethods: [
        charlieVerificationMethodKeyAgreeX255191,
//        charlieVerificationMethodKeyAgreeX255192,
//        charlieVerificationMethodKeyAgreeX255193,
//        charlieAuthMethod25519
    ],
    authentication: [.stringValue("did:example:charlie#key-1")],
    keyAgreement: [
        .stringValue("did:example:charlie#key-x25519-1"),
//        .stringValue("did:example:charlie#key-x25519-2"),
//        .stringValue("did:example:charlie#key-x25519-3")
    ],
    services: [
        .init(
            id: "did:example:123456789abcdefghi#didcomm-1",
            type: "",
            serviceEndpoint: AnyCodable(
                arrayLiteral: [
                    "uri": "did:example:mediator2",
                    "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"],
                    "routing_keys": ["did:example:mediator1#key-x25519-1"]
                ] as [String: Any]
            )
        )
    ]
)
