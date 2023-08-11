//
//  Message.swift
//  
//
//  Created by Gonçalo Frade on 11/08/2023.
//

import Foundation

struct Message {
    let id: String
    let body: String
    let type: String
    let typ: String
    let from: String?
    let to: [String]
    let createdTime: Date
    let expiresTime: Date
    let fromPrior: Any
    let fromPriorJwt: String
    let attachments: [Attachment]
    let pleaseAck: Bool?
    let ack: String?
    let thid: String?
    let pthid: String?
    let customHeaders: [String: String]
}
