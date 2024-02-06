import Foundation

/// Represents the result of routing a DIDComm message through one or more mediators.
///
/// This structure captures the entire routing path of a message as it traverses through
/// mediators towards the final recipient, including all intermediate steps and the resulting
/// encrypted messages generated at each step.
public struct RoutingResult {
    /// A node in the routing tree, representing a step in the message routing process.
    typealias RoutingResultNode = Node<Branch>
    
    /// Represents a branch in the routing path, detailing a single routing step.
    struct Branch {
        /// The identifier (DID) of the final recipient of the message.
        let finalRecipient: String
        /// The identifier (DID) of the next mediator or recipient in the routing path.
        let next: String
        /// An array of identifiers (DIDs) for the entities routed by this step.
        let to: [String]
        /// The encrypted message result for this particular routing step.
        let encryptedResult: EncryptedResult
    }
    
    /// Encapsulates the result of forwarding a message, including the final recipient and the route taken.
    public struct ForwardMessageResult {
        /// The identifier (DID) of the final recipient of the forwarded message.
        public let finalRecipient: String
        /// An ordered list of identifiers (DIDs) for the mediators that routed the message.
        public let routedBy: [String]
        /// The final encrypted forward message intended for the final recipient.
        public let forwardMessage: EncryptedResult
    }
    
    /// The root nodes of the routing tree, representing the starting points of different routing paths.
    let root: [RoutingResultNode]
    
    /// Computes a flat list of all forward messages generated during the routing process, organized by final recipient.
    public var forwardMessages: [ForwardMessageResult] {
        root.flatMap { node in
            node.leafs.map { leaf in
                let routedBy = leaf.map(\.value.to).flatMap { $0 }
                let finalRecipient = leaf.value.finalRecipient
                return ForwardMessageResult(
                    finalRecipient: finalRecipient,
                    routedBy: routedBy,
                    forwardMessage: leaf.value.encryptedResult
                )
            }
        }
    }
}
