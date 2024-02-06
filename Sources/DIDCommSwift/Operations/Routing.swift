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

struct Routing {
    
    struct DIDCommService {
        
        struct ServiceEndpoint {
            let uri: String
            let accept: [String]
            let routingKeys: [String]
        }
        
        let id: String
        let type: String
        let serviceEndpoint: [ServiceEndpoint]
    }
    
    let didResolver: DIDResolver
    let secretResolver: SecretResolver
    
    func packRouting(
        to: [String],
        packedMessage: String,
        encodingAlgorithm: AnonymousEncryptionAlgorithms = .a256CBCHS512
    ) async throws -> RoutingResult? {
        let servicesTree = try await ServiceTree(resolver: didResolver, to: to)
        
        let nodeResults = try await servicesTree.root.asyncMap { node in
            try await node.children.asyncMap {
                try await encryptNodeTreeForward(
                    $0,
                    nil,
                    lastPackedMessage: packedMessage,
                    algorithm: encodingAlgorithm
                )
            }
        }.flatMap { $0 }
        
        return nodeResults.isEmpty ? nil : RoutingResult(root: nodeResults)
    }
    
    func unpackRouting(messageData: Data) throws -> Data? {
        let message = try Message(from: messageData)
        guard
            message.type == ForwardMessage.messageType,
            let attachmentMessageData = message.attachments?.first?.data.getData()
        else {
            return nil
        }
        let messageData: Data
        switch attachmentMessageData {
        case .json(let value):
            messageData = try value.tryToData()
        case .base64(let value):
            messageData = value
        default:
            throw DIDCommError.invalidAttachmentDataType
        }
        return messageData
    }
    
    private func buildForwardMessage(to: [String], nextTo: String, lastPackedMessage: String) -> ForwardMessage {
        ForwardMessage(
            to: to,
            body: .init(next: nextTo),
            attachments: [
                .init(data: JsonAttachmentData(json: lastPackedMessage), mediaType: "application/json")
            ]
        )
    }
    
    private func encryptNodeTreeForward(
        _ node: Node<ServiceTree.Branch>,
        _ parentNode: Node<RoutingResult.Branch>?,
        lastPackedMessage: String,
        algorithm: AnonymousEncryptionAlgorithms
    ) async throws -> Node<RoutingResult.Branch> {
        guard let parentDID = node.parent?.value.uri else {
            throw DIDCommError.missingUri
        }
        let to = node.value.nextDID.map { node.value.routingKeys + [$0] } ?? node.value.routingKeys
        let forwardMessage = buildForwardMessage(
            to: to,
            nextTo: parentDID,
            lastPackedMessage: lastPackedMessage
        )
        let result = try await encrypt(
            message: forwardMessage.toMessage(),
            to: to,
            algorithm: algorithm
        )
        
        let resultNode = RoutingResult.RoutingResultNode(value: .init(
            finalRecipient: node.value.rootDID,
            next: parentDID,
            to: to,
            encryptedResult: result
        ))
        parentNode?.add(child: resultNode)
        if !node.isLeaf {
            try await node.children.asyncForEach {
                _ = try await encryptNodeTreeForward(
                    $0,
                    resultNode,
                    lastPackedMessage: result.packedMessage,
                    algorithm: algorithm
                )
            }
        }
        return resultNode.root
    }
    
    private func encrypt(
        message: Message, 
        to: [String],
        algorithm: AnonymousEncryptionAlgorithms
    ) async throws -> EncryptedResult {
        try await AnonEnvelopePack(
            message: message,
            to: to,
            algorithm: algorithm,
            fromPriorIssuerKid: nil,
            routingEnabled: false,
            signFrom: nil,
            didResolver: didResolver,
            secretResolver: secretResolver
        ).pack()
    }
}
