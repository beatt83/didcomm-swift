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

import DIDCore
import Foundation

struct SenderKeySelector {
    private let didResolver: DIDResolver
    private let secretResolver: SecretResolver
    
    init(didResolver: DIDResolver, secretResolver: SecretResolver) {
        self.didResolver = didResolver
        self.secretResolver = secretResolver
    }

    func findSigningKey(signFrom: String) async throws -> Key {
        guard let didFrom = DIDUrl(from: signFrom) else {
            throw DIDCommError.invalidDID(signFrom)
        }
        if didFrom.fragment != nil {
            guard let key = try await secretResolver.findKey(kid: signFrom) else {
                throw DIDCommError.secretNotFound(signFrom)
            }
            return try KeyHelper.fromSecret(key)
        } else {
            let document = try await  didResolver.resolve(did: didFrom.did)
            guard let authentication = document.parsedAuthentication.first(where: { $0.isSupportedAuthenticationMethod }) else {
                throw DIDCommError.secretNotFound(signFrom)
            }
            guard let key = try await secretResolver.findKey(kid: authentication.id) else {
                throw DIDCommError.secretNotFound(signFrom)
            }
            return try KeyHelper.fromSecret(key)
        }
    }
    
    func findAuthCryptKeys(from: String, to: [String]) async throws -> (Key, [Key]) {
        let keys = try await to
            .asyncMap { try await findAuthCryptKeys(from: from, to: $0) }
        guard let fromKey = keys.first?.0 else {
            throw DIDCommError.secretNotFound(from)
        }
        return (fromKey, keys.flatMap(\.1))
    }

    func findAuthCryptKeys(from: String, to: String) async throws -> (Key, [Key]) {
        guard let didFrom = DIDUrl(from: from) else {
            throw DIDCommError.invalidDID(from)
        }
        
        guard let didTo = DIDUrl(from: to) else {
            throw DIDCommError.invalidDID(to)
        }
        
        let toDocument = try await didResolver.resolve(did: didTo.did)
        
        if didFrom.fragment != nil {
            guard let secret = try await secretResolver.findKey(kid: from) else {
                throw DIDCommError.secretNotFound(from)
            }
            
            let sender = try KeyHelper.fromSecret(secret)
            let recipients = try findRecipientKeys(document: toDocument, to: to, curve: sender.curve)
            
            guard !recipients.isEmpty else {
                throw DIDCommError.unsupportedKey("", supported: ["X25519", "Ed25519"])
            }
            
            return (sender, recipients)
        } else {
            let fromDocument = try await didResolver.resolve(did: didFrom.did)
            
            for agreement in fromDocument.parsedKeyAgreement {
                if let secret = try await secretResolver.findKey(kid: agreement.id) {
                    let key = try KeyHelper.fromSecret(secret)
                    let recipients = try findRecipientKeys(document: toDocument, to: to, curve: key.curve)
                    if !recipients.isEmpty {
                        return (key, recipients)
                    }
                }
            }
            
            throw DIDCommError.unsupportedKey("", supported: ["X25519", "Ed25519"])
        }
    }
    
    func findAnonCryptKeys(to: [String]) async throws -> [Key] {
        try await to.asyncMap { try await findAnonCryptKeys(to: $0) }.flatMap { $0 }
    }

    func findAnonCryptKeys(to: String) async throws -> [Key] {
        guard let didTo = DIDUrl(from: to) else {
            throw DIDCommError.invalidDID(to)
        }
        let document = try await didResolver.resolve(did: didTo.did)
        if didTo.fragment != nil {
            guard let verificationMethod = document.verificationMethods.first(where: { $0.id == to }) else {
                return []
            }
            return [try KeyHelper.fromVerificationMethod(method: verificationMethod)]
        } else {
            return document.parsedKeyAgreement
                .filter({ $0.isSupportedAgreementMethod })
                .map { try? KeyHelper.fromVerificationMethod(method: $0) }
                .compactMap { $0 }
        }
    }

    private func findRecipientKeys(document: DIDDocument, to: String, curve: String) throws -> [Key] {
        guard
            let didTo = DIDUrl(from: to)
        else {
            throw DIDCommError.invalidDID(to)
        }
        if didTo.fragment != nil {
            guard
                let verificationMethod = document.verificationMethods.first(where: { $0.id == to }),
                let methodCurve = try? verificationMethod.getCurve(),
                curve == methodCurve
            else {
                return []
            }
            return [try KeyHelper.fromVerificationMethod(method: verificationMethod)]
        } else {
            return document.parsedKeyAgreement
                .filter {
                    $0.isSupportedAgreementMethod && (curve == (try? $0.getCurve()))
                }
                .map { try? KeyHelper.fromVerificationMethod(method: $0) }
                .compactMap { $0 }
        }
    }
}

extension DIDDocument {
    var parsedAuthentication: [VerificationMethod] {
        authentication?.map {
            switch $0 {
            case .stringValue(let value):
                return verificationMethods.first { $0.id == value }
            case .verificationMethod(let method):
                return method
            }
        }.compactMap { $0 } ?? []
    }
    
    var parsedKeyAgreement: [VerificationMethod] {
        keyAgreement?.map {
            switch $0 {
            case .stringValue(let value):
                return verificationMethods.first { $0.id == value }
            case .verificationMethod(let method):
                return method
            }
        }.compactMap { $0 } ?? []
    }
}

extension DIDDocument.VerificationMethod {
    fileprivate var isSupportedAgreementMethod: Bool {
        guard let type = KnownVerificationMaterialType(rawValue: self.type) else {
            return false
        }
        switch type {
        case .agreement:
            return true
        default:
            return false
        }
    }
    
    fileprivate var isSupportedAuthenticationMethod: Bool {
        guard let type = KnownVerificationMaterialType(rawValue: self.type) else {
            return false
        }
        switch type {
        case .authentication:
            return true
        default:
            return false
        }
    }
    
    fileprivate func getCurve() throws -> String {
        guard let type = KnownVerificationMaterialType(rawValue: self.type) else {
            throw DIDCommError.unsupportedKey("", supported: ["X25519", "Ed25519"])
        }
        switch type {
        case .agreement:
            return "X25519"
        default:
            return "Ed25519"
        }
    }
}
