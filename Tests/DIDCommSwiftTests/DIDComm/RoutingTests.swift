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

final class RoutingTests: XCTestCase {

    func testPackRoutingMessage() async throws {
        let didcomm = DIDComm(
            didResolver: DIDDocumentResolverMock.mockRouting(),
            secretResolver: AliceSecretResolverMock()
        )
        
        let message = Message.encryptedTextMessage
        let packed = try await didcomm.packEncrypted(params: .init(
            message: message,
            to: [bobDID],
            from: aliceDID,
            encAlgAuth: .a256CBCHS512
        ))
        let forwardMessages = packed.routingResult!.forwardMessages
        
        XCTAssertEqual(forwardMessages.count, 3) // Tree final forward messages
        XCTAssertTrue(packed.routingResult!.root.allSatisfy({ $0.value.finalRecipient == bobDID }))
        let mediator1Routing = packed.routingResult!.root[0]
        let mediator2Routing = packed.routingResult!.root[1]
        let mediator3Routing = packed.routingResult!.root[2]
        XCTAssertTrue(mediator1Routing.value.to.contains("did:example:bobMediator1"))
        XCTAssertTrue(mediator1Routing.children.isEmpty) // Just forwarded once
        XCTAssertEqual(forwardMessages[0].routedBy.count, 1) // Just routed by 1
        XCTAssertEqual(forwardMessages[0].sendTo, ["did:example:bobMediator1#key-x25519-1"])
        XCTAssertTrue(mediator2Routing.value.to.contains("did:example:bobMediator2"))
        XCTAssertEqual(mediator2Routing.children.count, 1) // Forwarded twice
        XCTAssertEqual(forwardMessages[1].routedBy.count, 2) // Just routed by 2
        XCTAssertEqual(forwardMessages[1].sendTo, ["did:example:bob#key-x25519-1"])
        XCTAssertTrue(mediator3Routing.value.to.contains("did:example:bobMediator3"))
        XCTAssertTrue(mediator3Routing.children.isEmpty) // Just forwarded once
        XCTAssertEqual(forwardMessages[2].routedBy.count, 2) // Just routed by 2
        XCTAssertEqual(forwardMessages[2].sendTo, ["did:example:bob#key-x25519-1", "did:example:bobMediator3#key-x25519-1"])
    }
    
    func testPackRoutingMultipleRecipientsMessage() async throws {
        let didcomm = DIDComm(
            didResolver: DIDDocumentResolverMock.mockRouting(),
            secretResolver: AliceSecretResolverMock()
        )
        
        let message = Message.encryptedTextMessage
        let packed = try await didcomm.packEncrypted(params: .init(
            message: message,
            to: [bobDID, aliceDID],
            from: aliceDID,
            encAlgAuth: .a256CBCHS512
        ))
        let forwardMessages = packed.routingResult!.forwardMessages
        
        XCTAssertEqual(forwardMessages.count, 4) // Tree final forward messages
        XCTAssertEqual(packed.routingResult!.root.filter({ $0.value.finalRecipient == bobDID }).count, 3)
        XCTAssertEqual(packed.routingResult!.root.filter({ $0.value.finalRecipient == aliceDID }).count, 1)
        let mediator1Routing = packed.routingResult!.root[0]
        let mediator2Routing = packed.routingResult!.root[1]
        let mediator3Routing = packed.routingResult!.root[2]
        let aliceRouting = packed.routingResult!.root[3]
        XCTAssertTrue(mediator1Routing.value.to.contains("did:example:bobMediator1"))
        XCTAssertTrue(mediator1Routing.children.isEmpty) // Just forwarded once
        XCTAssertEqual(forwardMessages[0].routedBy.count, 1) // Just routed by 1
        XCTAssertTrue(mediator2Routing.value.to.contains("did:example:bobMediator2"))
        XCTAssertEqual(mediator2Routing.children.count, 1) // Forwarded twice
        XCTAssertEqual(forwardMessages[1].routedBy.count, 2) // Just routed by 2
        XCTAssertEqual(forwardMessages[1].sendTo, ["did:example:bob#key-x25519-1"])
        XCTAssertTrue(mediator3Routing.value.to.contains("did:example:bobMediator3"))
        XCTAssertTrue(mediator3Routing.value.to.contains("did:example:bob#key-x25519-1"))
        XCTAssertTrue(mediator3Routing.children.isEmpty) // Just forwarded once
        XCTAssertEqual(forwardMessages[2].routedBy.count, 2) // Just routed by 2
        XCTAssertEqual(forwardMessages[2].sendTo, ["did:example:bob#key-x25519-1", "did:example:bobMediator3#key-x25519-1"])
        XCTAssertTrue(aliceRouting.value.to.contains("did:example:alice#key-x25519-1"))
        XCTAssertTrue(aliceRouting.children.isEmpty) // Just forwarded once
        XCTAssertEqual(forwardMessages[3].routedBy.count, 1) // Just routed by 2
        XCTAssertEqual(forwardMessages[3].sendTo, ["did:example:alice#key-x25519-1"])
    }
}
