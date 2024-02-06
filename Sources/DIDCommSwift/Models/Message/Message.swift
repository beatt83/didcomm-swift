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

/// Represents the MIME type of a DIDComm message.
public enum Typ: String, Codable {
    /// A message that is in plain text format without any encryption or signing.
    case plainText = "application/didcomm-plain+json"
    /// A message that has been signed by the sender's key but not encrypted.
    case signed = "application/didcomm-signed+json"
    /// A message that has been encrypted for the receiver, possibly also signed.
    case encrypted = "application/didcomm-encrypted+json"
}

/// Represents a DIDComm message, encapsulating data for secure communication.
public struct Message: Equatable {
    
    /// Represents claims transferred from a prior message, allowing for continuity and security context.
    public struct FromPrior {
        /// The issuer of the prior message.
        public let iss: String?
        /// The subject of the prior message.
        public let sub: String?
        /// The intended audience of the prior message.
        public let aud: String?
        /// The expiration time of the prior message.
        public let exp: Date?
        /// The time before which the prior message is not valid.
        public let nbf: Date?
        /// The issued at time of the prior message.
        public let iat: Date?
        /// The JWT ID of the prior message.
        public let jti: String?
        
        /// Initializes a new instance of `FromPrior`, which represents claims transferred from a prior message.
        /// This allows for continuity and security context between messages in DIDComm protocols.
        ///
        /// - Parameters:
        ///   - iss: The issuer of the prior message, typically the DID of the sender. Optional.
        ///   - sub: The subject of the prior message, which could be the DID of the intended recipient. Optional.
        ///   - aud: The intended audience of the prior message, often used in scenarios where the message is targeted to a specific party. Optional.
        ///   - exp: The expiration time of the prior message, indicating when the message is considered no longer valid. Optional.
        ///   - nbf: The "not before" time, indicating the earliest time at which the message is considered valid. Optional.
        ///   - iat: The "issued at" time, marking when the message was issued. This can be used for timing and ordering messages. Optional.
        ///   - jti: A unique identifier for the prior message, often used to prevent replay attacks or to reference the specific message in subsequent communications. Optional.
        ///
        /// This initializer allows for creating a `FromPrior` object that can be attached to a new DIDComm `Message` to provide context about a prior interaction or message.
        /// The inclusion of these fields supports various security and protocol continuity features, such as validating the sender, ensuring message timeliness, and linking related messages.
        public init(
            iss: String? = nil,
            sub: String? = nil,
            aud: String? = nil,
            exp: Date? = nil,
            nbf: Date? = nil,
            iat: Date? = nil,
            jti: String? = nil
        ) {
            self.iss = iss
            self.sub = sub
            self.aud = aud
            self.exp = exp
            self.nbf = nbf
            self.iat = iat
            self.jti = jti
        }
    }
    
    /// The unique identifier of the message.
    public let id: String
    /// The body of the message, containing the actual data in binary format.
    public let body: Data?
    /// A custom type identifier for the message, used for protocol-specific purposes.
    public let type: String
    /// The MIME type of the message, indicating how it is formatted and encrypted.
    public let typ: Typ
    /// The DID of the sender.
    public let from: String?
    /// An array of DIDs for the intended recipients of the message.
    public let to: [String]?
    /// The time when the message was created.
    public let createdTime: Date?
    /// The time when the message will expire and no longer be valid.
    public let expiresTime: Date?
    /// Claims transferred from a prior message, if applicable.
    public let fromPrior: FromPrior?
    /// A JWT representation of the `fromPrior` claims, if applicable.
    public let fromPriorJwt: String?
    /// An array of attachments included with the message.
    public let attachments: [Attachment]?
    /// A flag indicating whether the sender requests an acknowledgement for this message.
    public let pleaseAck: Bool?
    /// An acknowledgement ID, if this message is an acknowledgement for a previously received message.
    public let ack: String?
    /// The thread ID, used for threading messages in a conversation.
    public let thid: String?
    /// The parent thread ID, used for nesting conversations.
    public let pthid: String?
    /// Custom headers for protocol-specific use cases.
    public let customHeaders: [String: String]?
    
    /// Initializes a new instance of a DIDComm `Message`.
    /// - Parameters:
    ///   - id: A unique identifier for the message.
    ///   - body: The body of the message containing the actual data in binary format. Optional.
    ///   - type: A custom type identifier for the message, used for protocol-specific purposes.
    ///   - typ: The MIME type of the message, indicating how it's formatted and encrypted.
    ///   - from: The DID of the sender. Optional.
    ///   - to: An array of DIDs for the intended recipients of the message. Optional.
    ///   - createdTime: The creation time of the message. Optional.
    ///   - expiresTime: The expiration time of the message, after which it's no longer valid. Optional.
    ///   - fromPrior: Claims transferred from a prior message, if applicable. Optional.
    ///   - fromPriorJwt: A JWT representation of the `fromPrior` claims, if applicable. Optional.
    ///   - attachments: An array of attachments included with the message. Optional.
    ///   - pleaseAck: A flag indicating whether the sender requests an acknowledgement for this message. Optional.
    ///   - ack: An acknowledgement ID, if this message is an acknowledgement for a previously received message. Optional.
    ///   - thid: The thread ID, used for threading messages in a conversation. Optional.
    ///   - pthid: The parent thread ID, used for nesting conversations. Optional.
    ///   - customHeaders: Custom headers for protocol-specific use cases. Optional.
    /// - Returns: An instance of `Message` configured with the provided parameters.
    public init(
        id: String,
        body: Data? = nil,
        type: String,
        typ: Typ,
        from: String? = nil,
        to: [String]? = nil,
        createdTime: Date? = nil,
        expiresTime: Date? = nil,
        fromPrior: FromPrior? = nil,
        fromPriorJwt: String? = nil,
        attachments: [Attachment]? = nil,
        pleaseAck: Bool? = nil,
        ack: String? = nil,
        thid: String? = nil,
        pthid: String? = nil,
        customHeaders: [String : String]? = nil
    ) {
        self.id = id
        self.body = body
        self.type = type
        self.typ = typ
        self.from = from
        self.to = to
        self.createdTime = createdTime
        self.expiresTime = expiresTime
        self.fromPrior = fromPrior
        self.fromPriorJwt = fromPriorJwt
        self.attachments = attachments
        self.pleaseAck = pleaseAck
        self.ack = ack
        self.thid = thid
        self.pthid = pthid
        self.customHeaders = customHeaders
    }
    
    /// Updates the `fromPrior` and `fromPriorJwt` fields of a `Message` and returns a new `Message` instance.
    /// - Parameters:
    ///   - fromPrior: New `FromPrior` claims to be included in the message. Optional.
    ///   - jwt: A new JWT representation of the `fromPrior` claims. Optional.
    /// - Returns: A new `Message` instance with updated `fromPrior` and `fromPriorJwt` fields.
    public func updateFromPrior(fromPrior: FromPrior?, jwt: String?) -> Message {
        .init(
            id: id,
            body: body,
            type: type,
            typ: typ,
            from: from,
            to: to,
            createdTime: createdTime,
            expiresTime: expiresTime,
            fromPrior: fromPrior,
            fromPriorJwt: jwt,
            attachments: attachments,
            pleaseAck: pleaseAck,
            ack: ack,
            thid: thid,
            pthid: pthid,
            customHeaders: customHeaders
        )
    }
}

extension Message: Codable {}
extension Message.FromPrior: Codable {}
extension Message.FromPrior: Equatable {}

extension Message.FromPrior {
    
    init(fromJson: [String: Any]) throws {
        self.iss = fromJson["iss"] as? String
        self.sub = fromJson["sub"] as? String
        self.aud = fromJson["aud"] as? String
        self.exp = (fromJson["exp"] as? String)
            .flatMap { Date(fromDidcommString: $0) }
        self.nbf = (fromJson["nbf"] as? String)
            .flatMap { Date(fromDidcommString: $0) }
        self.iat = (fromJson["iat"] as? String)
            .flatMap { Date(fromDidcommString: $0) }
        self.jti = fromJson["jti"] as? String
    }
    
    func didcommJsonDic() -> [String: Any] {
        var jsonDic = [String: Any]()
        
        iss.map { jsonDic["iss"] = $0 }
        sub.map { jsonDic["sub"] = $0 }
        aud.map { jsonDic["aud"] = $0 }
        exp.map { jsonDic["exp"] = $0.formattedForDidcommPack() }
        nbf.map { jsonDic["nbf"] = $0.formattedForDidcommPack() }
        iat.map { jsonDic["iat"] = $0.formattedForDidcommPack() }
        jti.map { jsonDic["jti"] = $0 }
        
        return jsonDic
    }
}

private let registeredMessageFields = [
    "id",
    "type",
    "typ",
    "from",
    "to",
    "created_time",
    "expires_time",
    "from_prior",
    "from_prior_jwt",
    "attachments",
    "ack",
    "thid",
    "pthid",
    "please_ack",
    "body"
]

extension Message {
    
    /// Initializes a new `Message` instance from the given data object, which is expected to be a JSON representation of a message.
    ///
    /// This initializer attempts to deserialize the provided data into a JSON object and then initialize a `Message` instance using that JSON object.
    /// It encapsulates the process of data deserialization and message parsing, providing a straightforward way to create a `Message` from raw data.
    ///
    /// - Parameter data: The data object containing the JSON representation of a DIDComm message. This data should follow the DIDComm message structure.
    ///
    /// - Throws: This initializer can throw an error in several scenarios:
    ///   - `DIDCommError.somethingWentWrong`: If the data cannot be deserialized into a valid JSON object or if the resulting JSON does not conform to the expected structure for a DIDComm message.
    ///   - Any error thrown by `JSONSerialization.jsonObject(with:)`: If the data is not a valid JSON object.
    ///   - Any error thrown by `self.init(fromJson:)`: If initializing the `Message` with the JSON object fails due to missing required fields or invalid data types.
    ///
    /// - Returns: An instance of `Message` initialized with the data from the provided JSON object.
    ///
    /// Usage of this initializer simplifies the process of creating a `Message` from data received, for example, over a network or loaded from storage, ensuring that the data conforms to the expected DIDComm message format before proceeding with further processing.
    public init(from data: Data) throws {
        guard let messageJson = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw DIDCommError.malformedMessage(try data.tryToString())
        }
        try self.init(fromJson: messageJson)
    }
    
    init(fromJson: [String: Any]) throws {
        guard
            let id = fromJson["id"] as? String,
            let type = fromJson["type"] as? String,
            let typStr = fromJson["typ"] as? String,
            let typ = Typ(rawValue: typStr)
        else {
            throw DIDCommError.somethingWentWrong
        }
        
        self.id = id
        self.type = type
        self.typ = typ
        self.from = fromJson["from"] as? String
        self.to = fromJson["to"] as? [String]
        let createdTime = (fromJson["created_time"] as? String)
            .flatMap { Date(fromDidcommString: $0) } ?? (fromJson["created_time"] as? NSNumber)
            .flatMap { Date(fromDidcommInt: $0) }
        self.createdTime = createdTime
        
        let expiresTime = (fromJson["expires_time"] as? String)
            .flatMap { Date(fromDidcommString: $0) } ?? (fromJson["expires_time"] as? NSNumber)
            .flatMap { Date(fromDidcommInt: $0) }
        self.expiresTime = expiresTime
        self.fromPrior = try (fromJson["from_prior"] as? [String: Any])
            .map { try FromPrior(fromJson: $0) }
        self.fromPriorJwt = fromJson["from_prior_jwt"] as? String
        self.attachments = try (fromJson["attachments"] as? [[String: Any]])
            .map { try $0.map { try Attachment(fromJson: $0) } }
        self.ack = fromJson["ack"] as? String
        self.thid = fromJson["thid"] as? String
        self.pthid = fromJson["pthid"] as? String
        self.pleaseAck = (fromJson["please_ack"] as? NSNumber)?.boolValue
        let customHeadersFilter = fromJson.filter { !registeredMessageFields.contains($0.key) }
        if !customHeadersFilter.isEmpty {
            self.customHeaders = customHeadersFilter.compactMapValues { $0 as? String }
        } else {
            self.customHeaders = nil
        }
        
        self.body = try fromJson["body"].map {
            return try JSONSerialization.data(withJSONObject: $0)
        }
    }
    
    /// Converts the `Message` instance into a JSON `Data` object suitable for DIDComm communication.
    ///
    /// This method serializes the `Message` into a JSON representation, including all relevant fields and custom headers.
    /// It ensures that optional properties are included only when they are present and formats them appropriately for DIDComm specifications.
    ///
    /// - Throws: This method can throw errors in several scenarios:
    ///   - Any error from `JSONSerialization.data(withJSONObject:options:)`: If the message cannot be serialized into JSON data due to invalid content.
    ///   - `DIDCommError.somethingWentWrong`: If any part of the message contains data that cannot be serialized into JSON.
    ///   - Any error from processing the `body` data, if present, especially if it's not valid JSON.
    ///
    /// - Returns: A `Data` object representing the serialized JSON of the DIDComm message, ready for transmission or storage.
    ///
    /// The method carefully constructs a dictionary representing the message's properties, including handling of optional values like `from`, `to`, `createdTime`, and others.
    /// Dates are formatted specifically for DIDComm messaging, and attachments are processed to include their serialized JSON representations.
    /// This process ensures that the resulting JSON data adheres to the DIDComm message structure and specifications.
    public func didcommJson() throws -> Data {
        var jsonDic: [String: Any] = [
            "id": id,
            "type": type,
            "typ": typ.rawValue
        ]
        
        from.map { jsonDic["from"] = $0 }
        to.map { jsonDic["to"] = $0 }
        createdTime.map { jsonDic["created_time"] = $0.formattedForDidcommPack() }
        expiresTime.map { jsonDic["expires_time"] = $0.formattedForDidcommPack() }
        fromPrior.map { jsonDic["from_prior"] = $0.didcommJsonDic() }
        fromPriorJwt.map { jsonDic["from_prior_jwt"] = $0 }
        try attachments.map { jsonDic["attachments"] = try $0.map { try $0.didcommJsonDic() } }
        pleaseAck.map { jsonDic["please_ack"] = $0 }
        ack.map { jsonDic["ack"] = $0 }
        thid.map { jsonDic["thid"] = $0 }
        pthid.map { jsonDic["pthid"] = $0 }
        customHeaders?.forEach {
            jsonDic[$0] = $1
        }
        
        try body.map {
            let body = try $0.isEmpty ? "{}".tryToData() : $0
            let bodyJson = try JSONSerialization.jsonObject(with: body)
            jsonDic["body"] = bodyJson
        }
        
        let jsonData = try JSONSerialization.data(
            withJSONObject: jsonDic,
            options: [.withoutEscapingSlashes, .sortedKeys]
        )
        
        return jsonData
    }
}

extension Date {
    func formattedForDidcommPack() -> Int {
        Int(timeIntervalSince1970)
    }
    
    init?(fromDidcommString str: String) {
        if let dateSeconds = Double(str) {
            self = Date(timeIntervalSince1970: dateSeconds)
        } else {
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(secondsFromGMT: 0)
            if let date = formatter.date(from: str) {
                self = date
            } else {
                return nil
            }
        }
    }
    
    init?(fromDidcommInt time: NSNumber) {
        self = Date(timeIntervalSince1970: time.doubleValue)
    }
}
