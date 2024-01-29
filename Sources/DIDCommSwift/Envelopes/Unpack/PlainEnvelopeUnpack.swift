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

struct PlainEnvelopeUnpack {
    let packedMessage: Data
    let expectDecryptByAllKeys: Bool
    let didResolver: DIDResolver
    let secretResolver: SecretResolver
    
    func unpack(metadata: MetadataBuilder) async throws -> (message: Data, metadata: MetadataBuilder) {
        let keySelector = RecipientKeySelector(
            didResolver: didResolver,
            secretResolver: secretResolver
        )
        guard let messageJson = try JSONSerialization.jsonObject(with: packedMessage) as? [String: Any] else {
            throw DIDCommError.somethingWentWrong
        }
        let (message, fromPriorIssuerKid) = try await FromPrior.unpackFromPrior(
            message: try Message(fromJson: messageJson),
            keySelector: keySelector
        )
        
        var metadata = metadata
        metadata.fromPriorIssuerKid = fromPriorIssuerKid
        metadata.fromPriorJwt = message.fromPriorJwt
        return (message: try message.didcommJson(), metadata: metadata)
    }
}
