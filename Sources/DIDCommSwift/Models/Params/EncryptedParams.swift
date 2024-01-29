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

/// Pack Encrypted Message Parameters
public struct EncryptedParams {
    public let message: Message
    public let to: String
    public let from: String?
    public let signFrom: String?
    public let fromPriorIssuerKid: String?
    public let encAlgAuth: AuthCryptAlg?
    public let encAlgAnon: AnonCryptAlg?
    public let protectSenderId: Bool
    public let forward: Bool
    public let forwardHeaders: [String: String]?
    public let forwardServiceId: String?
    public let didResolver: DIDResolver?
    public let secretResolver: SecretResolver?

    public init(
        message: Message,
        to: String,
        from: String? = nil,
        signFrom: String? = nil,
        fromPriorIssuerKid: String? = nil,
        encAlgAuth: AuthCryptAlg? = nil,
        encAlgAnon: AnonCryptAlg? = nil,
        protectSenderId: Bool = false,
        forward: Bool = true,
        forwardHeaders: [String: String]? = nil,
        forwardServiceId: String? = nil,
        didResolver: DIDResolver? = nil,
        secretResolver: SecretResolver? = nil
    ) {
        // Your validation logic here (similar to Kotlin's build function)

        self.message = message
        self.to = to
        self.from = from
        self.signFrom = signFrom
        self.fromPriorIssuerKid = fromPriorIssuerKid
        self.encAlgAuth = encAlgAuth
        self.encAlgAnon = encAlgAnon
        self.protectSenderId = protectSenderId
        self.forward = forward
        self.forwardHeaders = forwardHeaders
        self.forwardServiceId = forwardServiceId
        self.didResolver = didResolver
        self.secretResolver = secretResolver
    }
}
