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

public protocol AttachmentData: Codable {
    var hash: String? { get }
    var jws: String? { get }
}

public struct LinksAttachmentData: AttachmentData, Equatable {
    public let hash: String?
    public let jws: String?
    public let links: [String]
    
    public init(
        hash: String? = nil,
        jws: String? = nil,
        links: [String]
    ) {
        self.hash = hash
        self.jws = jws
        self.links = links
    }
}

public struct Base64AttachmentData: AttachmentData, Equatable {
    public let hash: String?
    public let jws: String?
    public let base64: String
    
    public init(
        hash: String? = nil,
        jws: String? = nil,
        base64: String
    ) {
        self.hash = hash
        self.jws = jws
        self.base64 = base64
    }
}

public struct JsonAttachmentData: AttachmentData, Equatable {
    public let hash: String?
    public let jws: String?
    public let json: String
    
    public init(
        hash: String? = nil,
        jws: String? = nil,
        json: String
    ) {
        self.hash = hash
        self.jws = jws
        self.json = json
    }
}

public struct Attachment {
    public let id: String
    public let data: AttachmentData
    public let description: String?
    public let filename: String?
    public let mediaType: String?
    public let format: String?
    public let lastModTime: Date?
    public let byteCount: Int?
    
    public init(
        id: String,
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
    
    func didcommJsonDic() throws -> [String: Any] {
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
