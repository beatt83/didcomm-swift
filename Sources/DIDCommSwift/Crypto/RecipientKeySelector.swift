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

struct RecipientKeySelector {
    private let didResolver: DIDResolver
    private let secretResolver: SecretResolver

    init(didResolver: DIDResolver, secretResolver: SecretResolver) {
        self.didResolver = didResolver
        self.secretResolver = secretResolver
    }

    func findVerificationKey(signFrom: String) async throws -> Key {
        guard
            let didFrom = DIDUrl(from: signFrom),
            didFrom.fragment != nil
        else {
            throw DIDCommError.expectedDIDFragment(signFrom)
        }
        
        let document = try await didResolver.resolve(did: didFrom.did)
        
        guard let method = document.verificationMethods.first(where: { $0.id == signFrom }) else {
            throw DIDCommError.verificationMethodNotFoundForId(signFrom)
        }
        
        return try KeyHelper.fromVerificationMethod(method: method)
    }

    func findAuthCryptKeys(from: String, to: [String]) async throws -> (Key, [Key]) {
        guard
            let didFrom = DIDUrl(from: from),
            didFrom.fragment != nil
        else {
            throw DIDCommError.expectedDIDFragment(from)
        }
        
        let document = try await didResolver.resolve(did: didFrom.did)
        
        guard let method = document.verificationMethods.first(where: { $0.id == from }) else {
            throw DIDCommError.verificationMethodNotFoundForId(from)
        }
        
        let key = try KeyHelper.fromVerificationMethod(method: method)
        
        let recipientKeys = try await findRecipientKeys(to: to, curve: key.curve)
        
        return (key, recipientKeys)
    }

    func hasKeysForForwardNext(next: String) async throws -> Bool {
        let nextKids: [String]
        guard
            let didFrom = DIDUrl(from: next)
        else {
            throw DIDCommError.invalidDID(next)
        }
        
        if didFrom.fragment != nil {
            nextKids = [next]
        } else {
            let document = try await didResolver.resolve(did: didFrom.did)
            nextKids = document.keyAgreement?.map {
                switch $0 {
                case .stringValue(let id):
                    return id
                case .verificationMethod(let method):
                    return method.id
                }
            } ?? []
        }
        return try await !secretResolver.findKeys(kids: .init(nextKids)).isEmpty
    }

    func findAnonCryptKeys(to: [String]) async throws -> [Key] {
        try to.forEach {
            guard DIDUrl(from: $0) != nil else {
                throw DIDCommError.expectedDIDFragment($0)
            }
        }
        
        return try await findRecipientKeys(to: to, curve: nil)
    }

    private func findRecipientKeys(to: [String], curve: String?) async throws -> [Key] {
        let secrets = try await secretResolver.findKeys(kids: .init(to))
        guard !secrets.isEmpty else { throw DIDCommError.secretsNotFound(to) }
        
        let foundSecrets = try await secrets
            .asyncMap { try await secretResolver.findKey(kid: $0) }
            .compactMap { $0 }
        
        return try foundSecrets
            .map { secret in
                let key = try KeyHelper.fromSecret(secret)
                if let curve, curve != key.curve {
                    throw DIDCommError.unexpectedCurve(
                        id: secret.kid,
                        curve: key.curve,
                        expected: [curve]
                    )
                }
                return key
            }
    }
}
