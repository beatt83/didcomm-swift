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

final class PackPlainMessageTests: XCTestCase {

    func testPlainMessage() async throws {
        let didcomm = DIDComm(
            didResolver: DIDDocumentResolverMock.mock(),
            secretResolver: AliceSecretResolverMock()
        )
        
        let packed = try await didcomm.packPlainText(params: .init(
            message: Message.plainTextMessage
        ))
        
        let unpacked = try await didcomm.unpack(params: .init(packedMessage: packed.packedMessage))
        
        XCTAssertEqual(Message.plainTextMessage, unpacked.message)
    }
    
    func testPlainTextMessageWithFromPriorAndIssKid() async throws {
        let didcomm = DIDComm(
            didResolver: DIDDocumentResolverMock.mock(),
            secretResolver: AliceRotatedToCharlieSecretResolverMock()
        )
        
        for message in [Message.plainTextMessageFromPriorMinimal, Message.plainTextMessageFromPrior] {
            let packed = try await didcomm.packPlainText(params: .init(
                message: message,
                fromPriorIssuerKid: "did:example:alice#key-2"
            ))
            
            XCTAssertEqual(packed.fromPriorIssuerKid, "did:example:alice#key-2")
            
            let unpacked = try await didcomm.unpack(params: .init(packedMessage: packed.packedMessage))
            
            XCTAssertEqual(message, unpacked.message)
            XCTAssertEqual(unpacked.metadata.fromPriorIssuerKid, "did:example:alice#key-2")
        }
    }
}

