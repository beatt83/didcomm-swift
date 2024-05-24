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
    guard let didUrl = DIDUrl(from: to) else {
        throw DIDCommError.invalidDID(to)
    }
    
    let document = try await didResolver.resolve(did: didUrl.did)
    let routingTo = try getRoutingURIAndKeys(document: document)
    
    try await routingTo.asyncForEach {
        let nextDID = DIDUrl(from: $0.uri)?.did
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
        .first { (try? $0.toDIDCommService()) != nil }
        .map {
            try $0.toDIDCommService().serviceEndpoint
                .map { ($0.uri, $0.routingKeys) }
        } ?? []
}

private func getRoutingKeys(document: DIDDocument) throws -> [String] {
    try document.services?
        .first { (try? $0.toDIDCommService()) != nil }
        .flatMap {
            try $0.toDIDCommService().serviceEndpoint
                .flatMap(\.routingKeys)
        } ?? []
}

private extension AnyCodable {
    func toDIDCommService() throws -> Routing.DIDCommService {
        guard
            let dic = value as? [String: Any],
            let id = dic["id"] as? String,
            let type = dic["type"] as? String,
            type == didcommServiceType,
            let serviceEndpoint = dic["serviceEndpoint"]
        else { throw DIDCommError.notDidCommServiceType }
        
        switch serviceEndpoint {
        case let endpoint as String:
            return try parseServiceString(id: id, type: type, service: endpoint)
        case let endpoint as [String]:
            return try parseServiceStringArray(id: id, type: type, service: endpoint)
        case let endpoint as [String: Any]:
            return try parseServiceDic(id: id, type: type, service: endpoint)
        case let endpoint as [[String: Any]]:
            return try parseServiceArrayDic(id: id, type: type, service: endpoint)
        case let endpoint as AnyCodable:
            return try parseServiceAnyCodable(id: id, type: type, service: endpoint)
        case let endpoint as [AnyCodable]:
            return try parseServiceAnyCodableArray(id: id, type: type, service: endpoint)
        default:
            return .init(
                id: id,
                type: type,
                serviceEndpoint: []
            )
        }
    }
    
    func parseServiceString(id: String, type: String, service: String) throws -> Routing.DIDCommService {
        return .init(
            id: id,
            type: type,
            serviceEndpoint: [
                .init(uri: service, accept: [], routingKeys: [])
            ]
        )
    }
    
    func parseServiceStringArray(id: String, type: String, service: [String]) throws -> Routing.DIDCommService {
        return .init(
            id: id,
            type: type,
            serviceEndpoint: service.map {
                .init(uri: $0, accept: [], routingKeys: [])
            }
        )
    }
    
    func parseServiceDic(id: String, type: String, service: [String: Any]) throws -> Routing.DIDCommService {
        guard let uri = service["uri"] as? String else {
            throw DIDCommError.missingUri
        }
        return .init(
            id: id,
            type: type,
            serviceEndpoint: [
                .init(
                    uri: uri,
                    accept: (service["accept"] as? [String]) ?? [],
                    routingKeys: (service["routing_keys"] as? [String]) ?? []
                )
            ]
        )
    }
    
    func parseServiceArrayDic(id: String, type: String, service: [[String: Any]]) throws -> Routing.DIDCommService {
        return .init(
            id: id,
            type: type,
            serviceEndpoint: try service.map {
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
    }
    
    func parseServiceAnyCodableArray(id: String, type: String, service: [AnyCodable]) throws -> Routing.DIDCommService {
        return .init(
            id: id,
            type: type,
            serviceEndpoint: try service.flatMap { try parseServiceEndpoint(serviceEndpoint: $0) }
        )
    }
    
    func parseServiceAnyCodable(id: String, type: String, service: AnyCodable) throws -> Routing.DIDCommService {
        switch service.value {
        case let value as String:
            return try parseServiceString(id: id, type: type, service: value)
        case let value as [String]:
            return try parseServiceStringArray(id: id, type: type, service: value)
        case let value as [String: Any]:
            return try parseServiceDic(id: id, type: type, service: value)
        case let value as [[String: Any]]:
            return try parseServiceArrayDic(id: id, type: type, service: value)
        case let value as AnyCodable:
            return .init(
                id: id,
                type: type,
                serviceEndpoint: try parseServiceEndpoint(serviceEndpoint: value)
            )
        case let value as [AnyCodable]:
            return .init(
                id: id,
                type: type,
                serviceEndpoint: try value.flatMap { try parseServiceEndpoint(serviceEndpoint: $0) }
            )
        default:
            return .init(
                id: id,
                type: type,
                serviceEndpoint: []
            )
        }
    }
    
    func parseServiceEndpoint(serviceEndpoint: AnyCodable) throws -> [Routing.DIDCommService.ServiceEndpoint] {
        switch serviceEndpoint.value {
        case let value as String:
            return [
                .init(uri: value, accept: [], routingKeys: [])
            ]
        case let value as [String]:
            return value.map {
                .init(uri: $0, accept: [], routingKeys: [])
            }
        case let value as [String: Any]:
            guard let uri = value["uri"] as? String else {
                throw DIDCommError.missingUri
            }
            return [
                .init(
                    uri: uri,
                    accept: (value["accept"] as? [String]) ?? [],
                    routingKeys: (value["routing_keys"] as? [String]) ?? []
                )
            ]
        case let value as [[String: Any]]:
            return try value.map {
                guard let uri = $0["uri"] as? String else {
                    throw DIDCommError.missingUri
                }
                return .init(
                    uri: uri,
                    accept: ($0["accept"] as? [String]) ?? [],
                    routingKeys: ($0["routing_keys"] as? [String]) ?? []
                )
            }
        default:
            return []
        }
    }
}

