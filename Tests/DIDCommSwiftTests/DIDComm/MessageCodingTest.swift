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

final class MessageCodingTest: XCTestCase {
    func testExtraHeaders() throws {
        let message = Message(
            id: "test",
            body: nil,
            type: "test",
            typ: .plainText,
            from: "test",
            to: ["test1", "test2"],
            createdTime: Date(),
            expiresTime: Date(),
            fromPrior: nil,
            fromPriorJwt: nil,
            attachments: nil,
            pleaseAck: nil,
            ack: nil,
            thid: nil,
            pthid: nil,
            customHeaders: [
                "routing_all": "all"
            ]
        )
        
        let jsonData = try message.didcommJson()
        
        let parsed = try Message(fromJson: JSONSerialization.jsonObject(with: jsonData) as! [String: Any])
        
        XCTAssertEqual(message.id, parsed.id)
        XCTAssertEqual(message.body, parsed.body)
        XCTAssertEqual(message.type, parsed.type)
        XCTAssertEqual(message.typ, parsed.typ)
        XCTAssertEqual(message.from, parsed.from)
        XCTAssertEqual(message.to, parsed.to)
        XCTAssertEqual(message.fromPrior, parsed.fromPrior)
        XCTAssertEqual(message.fromPriorJwt, parsed.fromPriorJwt)
        XCTAssertEqual(message.attachments, parsed.attachments)
        XCTAssertEqual(message.pleaseAck, parsed.pleaseAck)
        XCTAssertEqual(message.ack, parsed.ack)
        XCTAssertEqual(message.thid, parsed.thid)
        XCTAssertEqual(message.pthid, parsed.pthid)
        XCTAssertEqual(message.customHeaders, parsed.customHeaders)
    }
    
    func testAttachment() throws {
        let attachment = Attachment(
            id: "test",
            data: JsonAttachmentData(json: "{}"),
            description: "testDescription",
            filename: "testFilename",
            mediaType: "testMediat",
            format: "testFormat",
            lastModTime: Date(),
            byteCount: 10
        )
        
        let jsonData = try attachment.didcommJsonDic()
        
        let parsed = try Attachment(fromJson: jsonData)
        
        XCTAssertEqual(attachment.id, parsed.id)
        XCTAssertEqual(attachment.description, parsed.description)
        XCTAssertEqual(attachment.filename, parsed.filename)
        XCTAssertEqual(attachment.mediaType, parsed.mediaType)
        XCTAssertEqual(attachment.format, parsed.format)
        XCTAssertEqual(attachment.byteCount, parsed.byteCount)
        XCTAssertNotNil(jsonData["media_type"])
        XCTAssertNotNil(jsonData["lastmod_time"])
        XCTAssertNotNil(jsonData["byte_count"])
    }
}
