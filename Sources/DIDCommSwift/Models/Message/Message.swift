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

public enum Typ: String, Codable {
    case plainText = "application/didcomm-plain+json"
    case signed = "application/didcomm-signed+json"
    case encrypted = "application/didcomm-encrypted+json"
}

public struct Message: Equatable {
    
    public struct FromPrior {
        public let iss: String?
        public let sub: String?
        public let aud: String?
        public let exp: Date?
        public let nbf: Date?
        public let iat: Date?
        public let jti: String?
        
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
    
    public let id: String
    public let body: Data?
    public let type: String
    public let typ: Typ
    public let from: String?
    public let to: [String]?
    public let createdTime: Date?
    public let expiresTime: Date?
    public let fromPrior: FromPrior?
    public let fromPriorJwt: String?
    public let attachments: [Attachment]?
    public let pleaseAck: Bool?
    public let ack: String?
    public let thid: String?
    public let pthid: String?
    public let customHeaders: [String: String]?
    
    public init(
        id: String,
        body: Data?,
        type: String,
        typ: Typ,
        from: String?,
        to: [String]?,
        createdTime: Date?,
        expiresTime: Date?,
        fromPrior: FromPrior?,
        fromPriorJwt: String?,
        attachments: [Attachment]?,
        pleaseAck: Bool?,
        ack: String?,
        thid: String?,
        pthid: String?,
        customHeaders: [String : String]?
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
    
    func didcommJson() throws -> Data {
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
