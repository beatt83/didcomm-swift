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
import XCTest

final class PackSignedMessageTests: XCTestCase {

    func testPackSignedMessage() async throws {
        let didcomm = DIDComm(
            didResolver: DIDDocumentResolverMock.mock(),
            secretResolver: AliceSecretResolverMock()
        )
        
        let packed = try await didcomm.packSigned(params: .init(
            message: Message.plainTextMessage,
            signFrom: "did:example:alice#key-3"
        ))
        
        let unpack = try await didcomm.unpack(params: .init(packedMessage: packed.packedMessage))
        
        XCTAssertEqual(Message.plainTextMessage, unpack.message)
    }
    
    func testUnpackSignedMessage() async throws {
        let expectedMessage = """
        {"id":"1234567890","typ":"application/didcomm-plain+json","type":"http://example.com/protocols/lets_do_lunch/1.0/proposal","from":"did:example:alice","to":["did:example:bob"],"created_time":1516269022,"expires_time":1516385931,"body":{"messagespecificattribute":"and its value"}}
        """.data(using: .utf8)!
        
        let signedMessage = """
        {"payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19","signatures":[{"protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ","signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ","header":{"kid":"did:example:alice#key-1"}}]}
        """.replacingWhiteSpacesAndNewLines()
        
        let didcomm = DIDComm(
            didResolver: DIDDocumentResolverMock.mock(),
            secretResolver: AliceSecretResolverMock()
        )
        
        
        let unpack = try await didcomm.unpack(params: .init(packedMessage: signedMessage))
        
        let jsonObj = try JSONSerialization.jsonObject(with: expectedMessage) as! [String: Any]
        
        XCTAssertEqual(unpack.message, try Message(fromJson: jsonObj))
    }
    
    func testSignedMessageTestVectors() async throws {
        for testVector in signingTestVectors {
            let didcomm = DIDComm(
                didResolver: DIDDocumentResolverMock.mock(),
                secretResolver: BobSecretResolverMock()
            )
            
            let unpacked = try await didcomm.unpack(params: .init(
                packedMessage: testVector.message,
                expectDecryptByAllKeys: true
            ))
            
            XCTAssertEqual(Message.plainTextMessage, unpacked.message)
            XCTAssertEqual(testVector.metadata.encrypted, unpacked.metadata.encrypted)
            XCTAssertEqual(testVector.metadata.authenticated, unpacked.metadata.authenticated)
            XCTAssertEqual(testVector.metadata.anonymousSender, unpacked.metadata.anonymousSender)
            XCTAssertEqual(testVector.metadata.nonRepudiation, unpacked.metadata.nonRepudiation)
            XCTAssertEqual(testVector.metadata.encAlgAnon, unpacked.metadata.encAlgAnon)
            XCTAssertEqual(testVector.metadata.encAlgAuth, unpacked.metadata.encAlgAuth)
            XCTAssertEqual(testVector.metadata.encryptedFrom, unpacked.metadata.encryptedFrom)
            XCTAssertEqual(testVector.metadata.encryptedTo?.sorted(), unpacked.metadata.encryptedTo?.sorted())
            XCTAssertEqual(testVector.metadata.signAlg, unpacked.metadata.signAlg)
            XCTAssertEqual(testVector.metadata.signFrom, unpacked.metadata.signFrom)
        }
    }
}
