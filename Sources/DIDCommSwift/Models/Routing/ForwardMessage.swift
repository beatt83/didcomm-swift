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

import Foundation

public struct ForwardMessage {
    
    static let messageType = "https://didcomm.org/routing/2.0/forward"
    
    public struct Body: Codable {
        public let next: String
    }
    
    public let type = messageType
    public let id: String
    public let to: [String]
    public let body: Body
    public let expiresTime: Date?
    public let attachments: [Attachment]
    public let customHeaders: [String: String]?
    
    public init(
        id: String = UUID().uuidString,
        to: [String],
        body: Body,
        expiresTime: Date? = nil,
        attachments: [Attachment],
        customHeaders: [String : String]? = nil
    ) {
        self.id = id
        self.to = to
        self.body = body
        self.expiresTime = expiresTime
        self.attachments = attachments
        self.customHeaders = customHeaders
    }
    
    public init(fromMessage: Message) throws {
        guard fromMessage.type == ForwardMessage.messageType else {
            throw DIDCommError.notForwardMessageType
        }
        
        guard let to = fromMessage.to else {
            throw DIDCommError.missingTo
        }
        
        guard let body = fromMessage.body else {
            throw DIDCommError.missingBody
        }
        
        guard let attachments = fromMessage.attachments else {
            throw DIDCommError.missingAttachment
        }
        
        self.id = fromMessage.id
        self.to = to
        self.body = try JSONDecoder().decode(Body.self, from: body)
        self.attachments = attachments
        self.expiresTime = fromMessage.expiresTime
        self.customHeaders = fromMessage.customHeaders
    }
    
    public func toMessage() throws -> Message {
        Message(
            id: id,
            body: try JSONEncoder.didcomm.encode(body),
            type: type,
            typ: .encrypted,
            from: nil,
            to: to,
            expiresTime: expiresTime,
            attachments: attachments,
            customHeaders: customHeaders
        )
    }
}
