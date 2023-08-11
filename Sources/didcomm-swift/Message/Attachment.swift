//
//  Attachment.swift
//  
//
//  Created by Gonçalo Frade on 11/08/2023.
//

import Foundation

struct Attachment {
    let id: String
    let data: Data
    let description: String?
    let filename: String?
    let mediaType: String?
    let format: String?
    let lastModTime: Date?
    let byteCount: Int?
}
