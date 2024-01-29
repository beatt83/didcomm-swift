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

final class RecipientKeySelectorTests: XCTestCase {
    
    func testFindVerificationKey() async throws {
        let recipientKeySelector = RecipientKeySelector(didResolver: DIDDocumentResolverMock.mock(), secretResolver: BobSecretResolverMock())
        let expected = "did:example:alice#key-2"
        let key = try await recipientKeySelector.findVerificationKey(signFrom: expected)
        XCTAssertEqual(expected, key.id)
    }
    
    func testFindAnonCryptoKeys() async throws {
        let recipientKeySelector = RecipientKeySelector(didResolver: DIDDocumentResolverMock.mock(), secretResolver: BobSecretResolverMock())
        let expected = [
            "did:example:bob#key-x25519-1",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-3"
        ]
        let keys = try await recipientKeySelector.findAnonCryptKeys(to: expected)
        XCTAssertEqual(expected, keys.map { $0.id }.sorted())
    }
    
    func testFindSecondAnonCryptoKey() async throws {
        let recipientKeySelector = RecipientKeySelector(didResolver: DIDDocumentResolverMock.mock(), secretResolver: BobSecretResolverMock())
        let recipient = [
            "did:example:bob#key-x25519-4",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-5"
        ]
        let expected = [
            "did:example:bob#key-x25519-2"
        ]
        let keys = try await recipientKeySelector.findAnonCryptKeys(to: recipient)
        XCTAssertEqual(expected, keys.map { $0.id })
    }
    
    func testFindAuthCryptoKeys() async throws {
        let recipientKeySelector = RecipientKeySelector(didResolver: DIDDocumentResolverMock.mock(), secretResolver: BobSecretResolverMock())
        let sender = "did:example:alice#key-x25519-1"
        let recipient = [
            "did:example:bob#key-x25519-1",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-3"
        ]
        let (from, to) = try await recipientKeySelector.findAuthCryptKeys(from: sender, to: recipient)
        let expectedFrom = "did:example:alice#key-x25519-1"
        let expectedTo = Set([
            "did:example:bob#key-x25519-1",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-3"
        ])
        XCTAssertEqual(expectedFrom, from.id)
        XCTAssertEqual(expectedTo, Set(to.map(\.id)))
    }
    
    func testDIDIsPassedToMethods() async throws {
        let recipientKeySelector = RecipientKeySelector(didResolver: DIDDocumentResolverMock.mock(), secretResolver: BobSecretResolverMock())
        
        do {
            _ = try await recipientKeySelector.findVerificationKey(signFrom: aliceDID)
            XCTFail()
        } catch {
        }
        do {
            _ = try await recipientKeySelector.findAuthCryptKeys(from: aliceDID, to: [bobDID])
            XCTFail()
        } catch {
        }
        do {
            _ = try await recipientKeySelector.findAnonCryptKeys(to: [bobDID])
            XCTFail()
        } catch {
        }
    }
    
    func testKeyNotFound() async throws {
        let recipientKeySelector = RecipientKeySelector(didResolver: DIDDocumentResolverMock.mock(), secretResolver: BobSecretResolverMock())
        let didUrl = "did:example:bob#key-x25519-4"
        
        do {
            _ = try await recipientKeySelector.findAnonCryptKeys(to: [didUrl])
            XCTFail()
        } catch {
        }
        
        do {
            _ = try await recipientKeySelector.findAuthCryptKeys(from: "did:example:alice#key-x25519-1", to: [didUrl])
            XCTFail()
        } catch {
        }
    }
    
    func testVerificationMethodNotFound() async throws {
        let recipientKeySelector = RecipientKeySelector(didResolver: DIDDocumentResolverMock.mock(), secretResolver: BobSecretResolverMock())
        let didUrl = "did:example:bob#key-4"
        
        do {
            _ = try await recipientKeySelector.findAuthCryptKeys(from: didUrl, to: [didUrl])
            XCTFail()
        } catch {
        }
        
        do {
            _ = try await recipientKeySelector.findVerificationKey(signFrom: didUrl)
            XCTFail()
        } catch {
        }
    }
    
    func testDIDDocNotResolved() async throws {
        let recipientKeySelector = RecipientKeySelector(didResolver: DIDDocumentResolverMock.mock(), secretResolver: BobSecretResolverMock())
        let didUrl = "\(nonaDID)#key-1"
        
        do {
            _ = try await recipientKeySelector.findVerificationKey(signFrom: didUrl)
            XCTFail()
        } catch {
        }
        
        do {
            _ = try await recipientKeySelector.findAuthCryptKeys(from: didUrl, to: [])
            XCTFail()
        } catch {
        }
    }
    
    func testEmptyDIDDoc() async throws {
        let recipientKeySelector = RecipientKeySelector(didResolver: DIDDocumentResolverMock.mock(), secretResolver: BobSecretResolverMock())
        let didUrl = "\(ellieDID)#key-2"
        
        do {
            _ = try await recipientKeySelector.findVerificationKey(signFrom: didUrl)
            XCTFail()
        } catch {
        }
        
        do {
            _ = try await recipientKeySelector.findAuthCryptKeys(from: didUrl, to: [])
            XCTFail()
        } catch {
        }
    }
    
    func testIncompatibleCrypto() async throws {
        let recipientKeySelector = RecipientKeySelector(didResolver: DIDDocumentResolverMock.mock(), secretResolver: BobSecretResolverMock())
        let bobDIDUrl = "did:example:bob#key-p256-1"
        let charlieDIDUrl = "did:example:charlie#key-x25519-1"
        
        do {
            _ = try await recipientKeySelector.findAuthCryptKeys(from: charlieDIDUrl, to: [bobDIDUrl])
            XCTFail()
        } catch {
        }
    }
    
    func testFindAnoncryptUnpackRecipientPrivateKeysPositiveSingleKey() async throws {
        let keySelector = RecipientKeySelector(didResolver: DIDDocumentResolverMock.mock(), secretResolver: BobSecretResolverMock())
        
        for secret in BobSecretResolverMock().secrets {
            let resJWK = try await keySelector.findAnonCryptKeys(to: [secret.kid]).map { $0.jwk }
            let key = try KeyHelper.fromSecret(secret)
            XCTAssertEqual(resJWK, [key.jwk])
        }
    }
    
    func testFindAnoncryptUnpackRecipientPrivateKeysAllKidsUnknown() async throws {
        let keySelector = RecipientKeySelector(didResolver: DIDDocumentResolverMock.mock(), secretResolver: BobSecretResolverMock())
        let toKids = [
            "\(bobDID)#unknown-key-1",
            "\(bobDID)#unknown-key-2"
        ]
        
        do {
            _ = try await keySelector.findAnonCryptKeys(to: toKids)
            XCTFail()
        } catch {}
    }
    
    // TODO: Check this test
//    func testFindAnoncryptUnpackRecipientPrivateKeysDifferentCurves() throws {
//        let keySelector = RecipientKeySelector(didResolver: DIDDocumentResolverMock.mock(), secretResolver: BobSecretResolverMock())
//        let secrets = try BobSecretResolverMock().secrets.map { try KeyHelper.fromSecret($0) }
//        let kids = secrets.map { $0.id }
//        let expected = secrets.map { $0.jwk }
//        let res = try keySelector.findAnonCryptKeys(to: kids).map { $0.jwk }
//
//        XCTAssertEqual(expected, res)
//    }
}
