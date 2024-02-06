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
@testable import DIDCommSwift
import Foundation

struct DIDDoccumentResolverInMemory: DIDResolver {
    let docs: [DIDDocument]
    
    func resolve(did: DID) throws -> DIDDocument {
        guard let document = docs.first(where: { $0.id == did.description }) else {
            throw DIDCommError.unableToResolveDID(did.description)
        }
        return document
    }
}

struct DIDDocumentResolverMock {
    static func mock() -> DIDDoccumentResolverInMemory {
        .init(docs: [
            didDocAliceSpecTestVectors,
            didDocBobTestVectors,
            didDocCharlie,
            didDocEllie,
        ])
    }
    
    static func mockNoSecrets() -> DIDDoccumentResolverInMemory {
        .init(docs: [
            didDocAliceSpecWithNoSecrets,
            didDocBobWithNoSecrets,
            didDocCharlie,
            didDocEllie
        ])
    }
    
    static func mockRouting() -> DIDDoccumentResolverInMemory {
        .init(docs: [
            didDocAliceSpecRoutingTestVectors,
            didDocBobSpecRoutingTestVectors,
            didDocBobSpecRoutingMediator1TestVectors,
            didDocBobSpecRoutingMediator2TestVectors,
            didDocBobSpecRoutingMediator3TestVectors
        ])
    }
}
