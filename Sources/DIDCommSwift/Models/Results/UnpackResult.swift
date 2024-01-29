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

/// Result of unpack operation.
public struct UnpackResult {
    public let message: Message
    public let metadata: Metadata
}

/// Metadata with details about the packed message. Can be used for MTC (message trust context) analysis.
public struct Metadata {
    public let encrypted: Bool
    public let authenticated: Bool
    public let nonRepudiation: Bool
    public let anonymousSender: Bool
    public let reWrappedInForward: Bool
    public let encryptedTo: [String]?
    public let encryptedFrom: String?
    public let signFrom: String?
    public let fromPriorIssuerKid: String?
    public let encAlgAuth: AuthCryptAlg?
    public let encAlgAnon: AnonCryptAlg?
    public let signAlg: SignAlg?
    public let signedMessage: [String: Any]?
    public let fromPriorJwt: String?
    
    public init(
        encrypted: Bool = false,
        authenticated: Bool = false,
        nonRepudiation: Bool = false,
        anonymousSender: Bool = false,
        reWrappedInForward: Bool = false,
        encryptedTo: [String]? = nil,
        encryptedFrom: String? = nil,
        signFrom: String? = nil,
        fromPriorIssuerKid: String? = nil,
        encAlgAuth: AuthCryptAlg? = nil,
        encAlgAnon: AnonCryptAlg? = nil,
        signAlg: SignAlg? = nil,
        signedMessage: [String: Any]? = nil,
        fromPriorJwt: String? = nil
    ) {
        self.encrypted = encrypted
        self.authenticated = authenticated
        self.nonRepudiation = nonRepudiation
        self.anonymousSender = anonymousSender
        self.reWrappedInForward = reWrappedInForward
        self.encryptedTo = encryptedTo
        self.encryptedFrom = encryptedFrom
        self.signFrom = signFrom
        self.fromPriorIssuerKid = fromPriorIssuerKid
        self.encAlgAuth = encAlgAuth
        self.encAlgAnon = encAlgAnon
        self.signAlg = signAlg
        self.signedMessage = signedMessage
        self.fromPriorJwt = fromPriorJwt
    }
}

// Assuming the other types (`Message`, `AuthCryptAlg`, `AnonCryptAlg`, `SignAlg`) are already defined.
