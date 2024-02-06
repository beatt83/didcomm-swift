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

struct PlainEnvelopePack {
    let message: Message
    let fromPriorIssuerKid: String?
    let routingEnabled: Bool
    let didResolver: DIDResolver
    let secretResolver: SecretResolver
    
    func pack() async throws -> PlainTextResult {
        let senderKeySelector = SenderKeySelector(didResolver: didResolver, secretResolver: secretResolver)

        let (message, fromPriorIssuerKid) = try await FromPrior.packFromPrior(
            message: message,
            fromPriorIssuerKid: fromPriorIssuerKid,
            keySelector: senderKeySelector
        )
        
        let messageJson = try message.didcommJson().tryToString()
        
        let routingResult: RoutingResult?
        
        if routingEnabled, let to = message.to {
            routingResult = try await Routing(
                didResolver: didResolver,
                secretResolver: secretResolver
            ).packRouting(
                to: to,
                packedMessage: messageJson
            )
        } else {
            routingResult = nil
        }
        
        return PlainTextResult(
            packedMessage: messageJson,
            fromPriorIssuerKid: fromPriorIssuerKid,
            routingResults: routingResult
        )
    }
}
