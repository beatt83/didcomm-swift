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

final class PackEncryptedMessageTests: XCTestCase {

    func testPackEncryptedMessage() async throws {
        let didcomm = DIDComm(
            didResolver: DIDDocumentResolverMock.mock(),
            secretResolver: AliceSecretResolverMock()
        )
        
        let message = Message.encryptedTextMessage
        let packed = try await didcomm.packEncrypted(params: .init(
            message: message,
            to: charlieDID,
            from: aliceDID,
            encAlgAuth: .a256CbcHs512Ecdh1puA256kw
        ))
        
        let didcommUnpack = DIDComm(
            didResolver: DIDDocumentResolverMock.mock(),
            secretResolver: CharlieSecretResolverMock()
        )
        
        let unpacked = try await didcommUnpack.unpack(
            params: .init(packedMessage: packed.packedMessage)
        )
        
        XCTAssertEqual(message, unpacked.message)
        print(packed.packedMessage)
        print()
    }
    
    func testUnpackEncryptedMessage() async throws {
        let message = """
        {"ciphertext":"4bTJeXcY_8GqbY-hLhwB-F3GcLXzyhhvRC91peBnx9u-vPL4ee8fPpRAdDUCcnjzTcFMDHXf4O2-mk115763f-mo5vDaGX6hb3kuimJLYxh2YPxBXVKOFgeF58bemOcCDr6dREPftRvEcis2zspSRPkT1GDFQmjdJPCBRAWFqrYImWBN9Myknr3cjL2JgEH-DSI5Jys4Ytn3YxrfNiCepVldLOiZvO2IjHjqvrZ7xFw-5Li2RRKuoiK2YaPrNcsAaZVA0JfgBcvYhxZUCAyVCogE984ISw40V01xH1aXh7Q3u53urQynMzv__hD44ZFt","iv":"5dLq35k9Fl13qsCzGtcK_g","protected":"eyJhbGciOiJFQ0RILTFQVStBMjU2S1ciLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwiYXB2IjoiR0NFeFVzbG1ONDZkVWQtcTFVMXBrWjhBeVZWbnVzRF9XOWhYQjcxUGJMcyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkJUcXlvM0ZNenFSRGZwWjdFdFJWX2FjVUlRNExaLXNQRDFGTDVOQlNtUUEifSwic2tpZCI6ImRpZDpleGFtcGxlOmFsaWNlI2tleS14MjU1MTktMSJ9","recipients":[{"encrypted_key":"wR9wlqiwiUHOaVQQGMIUKHNkmgNXdiLt-2TWhUZPOEY4vTANPnYaOztPTWQQYjHYGCZAEFQQheoiDYl9LOxzGD7AUU-lt4EW","header":{"kid":"did:example:charlie#key-x25519-1"}}],"tag":"v5P_k_HYL7JLmU2d7p6fQ2Jaj4v2eCe5V8BmtLJG87s"}
        """.replacingWhiteSpacesAndNewLines()
        
        let didcomm = DIDComm(
            didResolver: DIDDocumentResolverMock.mock(),
            secretResolver: CharlieSecretResolverMock()
        )
        
        let unpack = try await didcomm.unpack(params: .init(packedMessage: message))
        
        print(unpack.message)
    }
    
    func testEncryptedMessageTestVectors() async throws {
        for testVector in encryptionTestVectors {
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
