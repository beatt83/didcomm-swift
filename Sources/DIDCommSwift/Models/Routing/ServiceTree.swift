//
//  File.swift
//  
//
//  Created by Gonçalo Frade on 05/02/2024.
//
import DIDCore
import Foundation

private let didcommServiceType = "DIDCommMessaging"

struct ServiceTree {
    struct Branch {
        let rootDID: String
        let uri: String
        let routingKeys: [String]
        let nextDID: String?
    }
    
    let root: [Node<Branch>]
    
    init(resolver: DIDResolver, to: [String]) async throws {
        let nodes = try await to.asyncMap {
            let rootNode = Node<Branch>.init(
                value: .init(
                    rootDID: $0,
                    uri: $0,
                    routingKeys: [],
                    nextDID: nil
            ))
            try await buildBranchsTree(
                didResolver: resolver,
                to: $0,
                parentNode: rootNode
            )
            return rootNode
        }
        
        self.root = nodes
    }
    
    func getAllMaterialsForBranchLevel(_ level: Int) -> (dids: [String], keys: [String]) {
        let levelNodes = root.flatMap { $0.getChildsForLevel(level) }
        let dids = levelNodes.map(\.value.uri)
        let keys = levelNodes.flatMap(\.value.routingKeys)
        return (dids, keys)
    }
    
    func getMaxLevelNumber() -> Int {
        root.flatMap(\.leafs).map(\.level).max() ?? 0
    }
}

private func buildBranchsTree(
    didResolver: DIDResolver,
    to: String,
    parentNode: Node<ServiceTree.Branch>
) async throws {
    guard let did = DID(from: to) else {
        throw DIDCommError.invalidDID(to)
    }
    
    let document = try await didResolver.resolve(did: did)
    let routingTo = try getRoutingURIAndKeys(document: document)
    
    try await routingTo.asyncForEach {
        let nextDID = DID(from: $0.uri)
        guard nextDID != nil || !$0.keys.isEmpty else {
            return
        }
        
        let newNode = Node<ServiceTree.Branch>.init(value: .init(
            rootDID: parentNode.value.rootDID,
            uri: $0.uri,
            routingKeys: $0.keys,
            nextDID: nextDID?.description
        ))
        parentNode.add(child: newNode)
        
        if let nextDIDStr = nextDID?.description {
            try await buildBranchsTree(
                didResolver: didResolver,
                to: nextDIDStr,
                parentNode: newNode
            )
        }
    }
}

private func getRoutingURIAndKeys(document: DIDDocument) throws -> [(uri: String, keys: [String])] {
    try document.services?
        .first { $0.type.contains("DIDCommMessaging") }
        .map {
            try $0.toDIDCommService().serviceEndpoint
                .map { ($0.uri, $0.routingKeys) }
        } ?? []
}

private func getRoutingKeys(document: DIDDocument) throws -> [String] {
    try document.services?
        .first { $0.type.contains("DIDCommMessaging") }
        .flatMap {
            try $0.toDIDCommService().serviceEndpoint
                .flatMap(\.routingKeys)
        } ?? []
}

private extension DIDDocument.Service {
    func toDIDCommService() throws -> Routing.DIDCommService {
        guard self.type == didcommServiceType else {
            throw DIDCommError.notDidCommServiceType
        }
        switch self.serviceEndpoint.value {
        case let value as String:
            return .init(
                id: self.id,
                type: self.type,
                serviceEndpoint: [
                    .init(uri: value, accept: [], routingKeys: [])
                ]
            )
        case let value as [String]:
            return .init(
                id: self.id,
                type: self.type,
                serviceEndpoint: value.map {
                    .init(uri: $0, accept: [], routingKeys: [])
                }
            )
        case let value as [String: Any]:
            guard let uri = value["uri"] as? String else {
                throw DIDCommError.missingUri
            }
            return .init(
                id: self.id,
                type: self.type,
                serviceEndpoint: [
                    .init(
                        uri: uri,
                        accept: (value["accept"] as? [String]) ?? [],
                        routingKeys: (value["routing_keys"] as? [String]) ?? []
                    )
                ]
            )
        case let value as [[String: Any]]:
            return .init(
                id: self.id,
                type: self.type,
                serviceEndpoint: try value.map {
                    guard let uri = $0["uri"] as? String else {
                        throw DIDCommError.missingUri
                    }
                    return .init(
                        uri: uri,
                        accept: ($0["accept"] as? [String]) ?? [],
                        routingKeys: ($0["routing_keys"] as? [String]) ?? []
                    )
                }
            )
        default:
            return .init(
                id: self.id,
                type: self.type,
                serviceEndpoint: []
            )
        }
    }
}

