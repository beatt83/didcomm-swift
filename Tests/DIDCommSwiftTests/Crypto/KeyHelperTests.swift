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
@testable import DIDCommSwift
import XCTest

class KeyTests: XCTestCase {

    let okpVerificationMaterial = Data("""
        {
            "kty": "OKP",
            "crv": "X25519",
            "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
        }
    """.utf8)

    let okpSecretMaterial = Data("""
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
            "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY"
        }
    """.utf8)

    let ecVerificationMaterial = Data("""
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
            "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
        }
    """.utf8)
    
    func testExtractOKPKeyFromJsonWebKey2020VerificationMethod() throws {
        let key = try KeyHelper.fromVerificationMethod(method: DIDDocument.VerificationMethod(
            id: "did:example:alice#key-x25519-1",
            controller: "did:example:alice",
            type: "JsonWebKey2020",
            material: VerificationMaterial(format: .jwk, value: okpVerificationMaterial)
        ))
        
        XCTAssertEqual("did:example:alice#key-x25519-1", key.id)
        // You'll need a way to extract curve from Key object. Assuming there's a property called curve.
        XCTAssertEqual("X25519", key.curve)
//        XCTAssertEqual(JWK(kty: "OKP", crv: "X25519", x: "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"), key.jwk)
    }

    func testExtractOKPKeyFromJsonWebKey2020Secret() throws {
        let key = try KeyHelper.fromSecret(Secret(
            kid: "did:example:alice#key-ed25519-2",
            type: .authentication(.jsonWebKey2020),
            verificationMaterial: VerificationMaterial(format: .jwk, value: okpSecretMaterial)
        ))
        
        XCTAssertEqual("did:example:alice#key-ed25519-2", key.id)
        // You'll need a way to extract curve from Key object. Assuming there's a property called curve.
        XCTAssertEqual("Ed25519", key.curve)
//        XCTAssertEqual(JWK(kty: "OKP", crv: "Ed25519", x: "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww", d: "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY"), key.jwk)
    }

    func testExtractECKeyFromJsonWebKey2020VerificationMethod() throws {
        let key = try KeyHelper.fromVerificationMethod(method: DIDDocument.VerificationMethod(
            id: "did:example:alice#key-p256-1",
            controller: "did:example:alice",
            type: "JsonWebKey2020",
            material: VerificationMaterial(format: .jwk, value: ecVerificationMaterial)
        ))
        
        XCTAssertEqual("did:example:alice#key-p256-1", key.id)
        // You'll need a way to extract curve from Key object. Assuming there's a property called curve.
        XCTAssertEqual("P-256", key.curve)
//        XCTAssertEqual(JWK(kty: "EC", crv: "P-256", x: "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE", y: "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"), key.jwk)
    }
    
    func testExtractECKeyFromJsonWebKey2020Secret() throws {
        let secret = Secret(
            kid: "did:example:alice#key-p256-2",
            type: .authentication(.jsonWebKey2020),
            verificationMaterial: VerificationMaterial(
                format: .jwk,
                value: Data("""
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                    "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w",
                    "d": "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A"
                }
                """.utf8)
            )
        )
        
        let key = try KeyHelper.fromSecret(secret)
        XCTAssertEqual("did:example:alice#key-p256-2", key.id)
        XCTAssertEqual("P-256", key.curve)
//        XCTAssertEqual(JWK(kty: "EC", crv: "P-256", x: "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY", y: "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w", d: "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A"), key.jwk)
    }

    func testExtractKeyFromX25519KeyAgreementKey2019VerificationMethod() throws {
        let method = DIDDocument.VerificationMethod(
            id: "did:example:dave#key-x25519-1",
            controller: "did:example:dave",
            type: "X25519KeyAgreementKey2019", // Ensure this string matches the rawValue of the corresponding enum case
            material: VerificationMaterial(
                format: .base58,
                value: Data("JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr".utf8)
            )
        )
        
        let key = try KeyHelper.fromVerificationMethod(method: method)
        XCTAssertEqual("did:example:dave#key-x25519-1", key.id)
        XCTAssertEqual("X25519", key.curve)
//        XCTAssertEqual(JWK(kty: "OKP", crv: "X25519", x: "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik"), key.jwk)
    }
}

extension JWK: Equatable {
    public static func == (lhs: JWK, rhs: JWK) -> Bool {
        lhs.kty == rhs.kty &&
        lhs.crv == rhs.crv &&
        lhs.x == rhs.x &&
        lhs.y == rhs.y &&
        lhs.d == rhs.d &&
        lhs.kid == rhs.kid
    }
}
