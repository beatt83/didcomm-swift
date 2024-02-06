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

/// Defines the type of data contained within an attachment.
public enum DataType {
    /// Represents data that is formatted as a JSON string.
    case json(String)
    /// Represents data that is encoded in base64 format.
    case base64(Data)
    /// Represents a list of links as data.
    case links([String])
}

/// Defines the requirements for attachment data in a DIDComm message, including optional hash and JWS (JSON Web Signature) properties.
public protocol AttachmentData: Codable {
    /// An optional hash of the data, used for data integrity verification.
    var hash: String? { get }
    /// An optional JSON Web Signature, used for verifying the authenticity of the data.
    var jws: String? { get }
    /// Retrieves the data in its specific format (`DataType`).
    func getData() -> DataType
}

/// Represents attachment data consisting of a list of links (URLs).
public struct LinksAttachmentData: AttachmentData, Equatable {
    /// An optional hash of the links data.
    public let hash: String?
    /// An optional JSON Web Signature of the links data.
    public let jws: String?
    /// The list of links (URLs) as the attachment data.
    public let links: [String]
    
    /// Initializes a new instance of links attachment data.
    /// - Parameters:
    ///   - hash: An optional hash for verifying data integrity.
    ///   - jws: An optional JSON Web Signature for data authentication.
    ///   - links: The actual links data.
    public init(
        hash: String? = nil,
        jws: String? = nil,
        links: [String]
    ) {
        self.hash = hash
        self.jws = jws
        self.links = links
    }
    
    /// Returns the data type as `.links`, encapsulating the links provided.
    public func getData() -> DataType {
        .links(links)
    }
}

/// Represents attachment data encoded in base64 format.
public struct Base64AttachmentData: AttachmentData, Equatable {
    /// An optional hash of the base64 encoded data.
    public let hash: String?
    /// An optional JSON Web Signature of the base64 encoded data.
    public let jws: String?
    /// The base64 encoded string.
    public let base64: String
    
    /// Initializes a new instance of base64 attachment data.
    /// - Parameters:
    ///   - hash: An optional hash for data integrity verification.
    ///   - jws: An optional JSON Web Signature for authentication.
    ///   - base64: The base64 encoded data.
    public init(
        hash: String? = nil,
        jws: String? = nil,
        base64: String
    ) {
        self.hash = hash
        self.jws = jws
        self.base64 = base64
    }
    
    /// Returns the data type as `.base64`, converting the base64 string to `Data`.
    public func getData() -> DataType {
        .base64(Data(base64URLEncoded: base64) ?? Data())
    }
}

/// Represents attachment data formatted as a JSON string.
public struct JsonAttachmentData: AttachmentData, Equatable {
    /// An optional hash of the JSON data.
    public let hash: String?
    /// An optional JSON Web Signature of the JSON data.
    public let jws: String?
    /// The JSON string representing the attachment data.
    public let json: String
    
    /// Initializes a new instance of JSON attachment data.
    /// - Parameters:
    ///   - hash: An optional hash for verifying the data's integrity.
    ///   - jws: An optional JSON Web Signature for verifying authenticity.
    ///   - json: The JSON formatted data.
    public init(
        hash: String? = nil,
        jws: String? = nil,
        json: String
    ) {
        self.hash = hash
        self.jws = jws
        self.json = json
    }
    
    /// Returns the data type as `.json`, containing the JSON string.
    public func getData() -> DataType {
        .json(json)
    }
}

/// Represents an attachment within a DIDComm message.
public struct Attachment {
    /// A unique identifier for the attachment.
    public let id: String
    /// The data of the attachment, conforming to `AttachmentData`.
    public let data: AttachmentData
    /// An optional description of the attachment.
    public let description: String?
    /// An optional filename for the attachment.
    public let filename: String?
    /// An optional media type of the attachment.
    public let mediaType: String?
    /// An optional format of the attachment.
    public let format: String?
    /// An optional timestamp of the last modification time.
    public let lastModTime: Date?
    /// An optional count of bytes for the attachment data.
    public let byteCount: Int?
    
    /// Initializes a new attachment with provided details.
    /// - Parameters:
    ///   - id: A unique identifier for the attachment. Defaults to a UUID string.
    ///   - data: The attachment data.
    ///   - description: A description of the attachment. Optional.
    ///   - filename: A filename for the attachment. Optional.
    ///   - mediaType: The media type of the attachment. Optional.
    ///   - format: The format of the attachment. Optional.
    ///   - lastModTime: The last modification time of the attachment. Optional.
    ///   - byteCount: The size of the attachment in bytes. Optional.
    public init(
        id: String = UUID().uuidString,
        data: AttachmentData,
        description: String? = nil,
        filename: String? = nil,
        mediaType: String? = nil,
        format: String? = nil,
        lastModTime: Date? = nil,
        byteCount: Int? = nil
    ) {
        self.id = id
        self.data = data
        self.description = description
        self.filename = filename
        self.mediaType = mediaType
        self.format = format
        self.lastModTime = lastModTime
        self.byteCount = byteCount
    }
}

extension Attachment: Codable {
    enum CodingKeys: String, CodingKey {
        case id
        case data
        case description
        case filename
        case mediaType
        case format
        case lastModTime
        case byteCount
        case type
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        let type = try container.decode(String.self, forKey: .type)
        
        switch type {
        case "links":
            data = try container.decode(LinksAttachmentData.self, forKey: .data)
        case "base64":
            data = try container.decode(Base64AttachmentData.self, forKey: .data)
        case "json":
            data = try container.decode(JsonAttachmentData.self, forKey: .data)
        default:
            throw DecodingError.dataCorruptedError(forKey: .type, in: container, debugDescription: "Invalid type value")
        }
        
        description = try container.decodeIfPresent(String.self, forKey: .description)
        filename = try container.decodeIfPresent(String.self, forKey: .filename)
        mediaType = try container.decodeIfPresent(String.self, forKey: .mediaType)
        format = try container.decodeIfPresent(String.self, forKey: .format)
        lastModTime = try container.decodeIfPresent(Date.self, forKey: .lastModTime)
        byteCount = try container.decodeIfPresent(Int.self, forKey: .byteCount)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        
        switch data {
        case is LinksAttachmentData:
            try container.encode("links", forKey: .type)
            try container.encode(data as! LinksAttachmentData, forKey: .data)
        case is Base64AttachmentData:
            try container.encode("base64", forKey: .type)
            try container.encode(data as! Base64AttachmentData, forKey: .data)
        case is JsonAttachmentData:
            try container.encode("json", forKey: .type)
            try container.encode(data as! JsonAttachmentData, forKey: .data)
        default:
            throw EncodingError.invalidValue(data, EncodingError.Context(codingPath: [CodingKeys.data], debugDescription: "Invalid data type"))
        }
        
        try container.encodeIfPresent(description, forKey: .description)
        try container.encodeIfPresent(filename, forKey: .filename)
        try container.encodeIfPresent(mediaType, forKey: .mediaType)
        try container.encodeIfPresent(format, forKey: .format)
        try container.encodeIfPresent(lastModTime, forKey: .lastModTime)
        try container.encodeIfPresent(byteCount, forKey: .byteCount)
    }
}

extension Attachment: Equatable {
    public static func == (lhs: Attachment, rhs: Attachment) -> Bool {
        let dataEqual: Bool
        switch (lhs.data, rhs.data) {
        case (let lhsData as LinksAttachmentData, let rhsData as LinksAttachmentData):
            dataEqual = lhsData == rhsData
        case (let lhsData as Base64AttachmentData, let rhsData as Base64AttachmentData):
            dataEqual = lhsData == rhsData
        case (let lhsData as JsonAttachmentData, let rhsData as JsonAttachmentData):
            dataEqual = lhsData == rhsData
        default:
            return false
        }
        return lhs.id == rhs.id &&
        lhs.format == rhs.format &&
        lhs.filename == rhs.filename &&
        lhs.description == rhs.description &&
        lhs.lastModTime == rhs.lastModTime &&
        lhs.mediaType == rhs.mediaType &&
        dataEqual
    }
}

extension AttachmentData {
    
    /// Serializes the attachment data into a dictionary suitable for JSON representation in DIDComm messages.
    ///
    /// This method constructs a dictionary containing the attachment's data along with its optional hash and JWS (JSON Web Signature).
    /// It handles different types of attachment data (`LinksAttachmentData`, `Base64AttachmentData`, `JsonAttachmentData`) specifically,
    /// ensuring the correct representation for each type in the resulting JSON structure.
    ///
    /// - Throws:
    ///   - `DIDCommError.somethingWentWrong`: If the attachment data cannot be properly serialized into JSON. This could occur, for example,
    ///     if JSON data within a `JsonAttachmentData` instance is malformed or cannot be encoded into UTF-8.
    ///   - Any error thrown by `JSONSerialization.jsonObject(with:)` when attempting to serialize JSON string data into a JSON object.
    ///
    /// - Returns: A dictionary representing the serialized form of the attachment data, including `hash` and `JWS` if present,
    ///   and the data itself in a format appropriate for inclusion in a DIDComm message JSON structure.
    ///
    /// The method dynamically checks the type of the conforming instance and serializes its contents accordingly.
    /// For `LinksAttachmentData`, it includes a list of links; for `Base64AttachmentData`, it includes a base64-encoded string;
    /// and for `JsonAttachmentData`, it attempts to serialize the JSON string into a JSON object for embedding within the dictionary.
    public func didcommJsonDic() throws -> [String: Any] {
        var jsonDic = [String: Any]()
        hash.map { jsonDic["hash"] = $0 }
        jws.map { jsonDic["jws"] = $0 }
        switch self {
        case let data as LinksAttachmentData:
            jsonDic["links"] = data.links
        case let data as Base64AttachmentData:
            jsonDic["base64"] = data.base64
        case let data as JsonAttachmentData:
            guard let jsonData = data.json.data(using: .utf8) else {
                throw DIDCommError.somethingWentWrong
            }
            let json = try JSONSerialization.jsonObject(with: jsonData)
            jsonDic["json"] = json
        default:
            break
        }
        
        return jsonDic
    }
}

extension Attachment {
    
    init(fromJson: [String: Any]) throws {
        guard
            let id = fromJson["id"] as? String,
            let data = fromJson["data"] as? [String: Any]
        else {
            throw DIDCommError.somethingWentWrong
        }
        
        self.id = id
        self.data = try attachmentDataFromJson(data)
        self.format = fromJson["format"] as? String
        self.filename = fromJson["filename"] as? String
        self.mediaType = fromJson["mediaType"] as? String
        self.byteCount = (fromJson["byteCount"] as? NSNumber)?.intValue
        self.lastModTime = (fromJson["lastModTime"] as? String)
            .flatMap { Date(fromDidcommString: $0) }
        self.description = fromJson["description"] as? String
    }
    
    func didcommJsonDic() throws -> [String: Any] {
        var jsonDic: [String: Any] = [
            "id": id,
            "data": try data.didcommJsonDic()
        ]
        
        description.map { jsonDic["description"] = $0 }
        filename.map { jsonDic["filename"] = $0 }
        mediaType.map { jsonDic["mediaType"] = $0 }
        format.map { jsonDic["format"] = $0 }
        lastModTime.map { jsonDic["lastModTime"] = $0.formattedForDidcommPack()}
        byteCount.map { jsonDic["byteCount"] = $0 }
        
        return jsonDic
    }
}

private func attachmentDataFromJson(_ fromJson: [String: Any]) throws -> AttachmentData {
    let hash = fromJson["hash"] as? String
    let jws = fromJson["jws"] as? String
    if let links = fromJson["links"] as? [String] {
        return LinksAttachmentData(
            hash: hash,
            jws: jws,
            links: links
        )
    } else if let base64 = fromJson["base64"] as? String {
        return Base64AttachmentData(
            hash: hash,
            jws: jws,
            base64: base64
        )
    } else if
        let json = fromJson["json"]
    {
        let jsonData = try JSONSerialization.data(withJSONObject: json)
        guard let jsonString = String(data: jsonData, encoding: .utf8) else {
            throw DIDCommError.somethingWentWrong
        }
        return JsonAttachmentData(
            hash: hash,
            jws: jws,
            json: jsonString
        )
    }
    throw DIDCommError.somethingWentWrong
}
