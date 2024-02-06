import Foundation

final class Node<Value> {
    let value: Value
    private(set) var parent: Node?
    private(set) var children: [Node]
    
    init(value: Value, parent: Node? = nil, children: [Node] = []) {
        self.value = value
        self.parent = parent
        self.children = children
    }
    
    func add(child: Node) {
        children.append(child)
        child.parent = self
    }
}

extension Node {
    var isLeaf: Bool { children.isEmpty }
    var isRoot: Bool { parent == nil }
}

extension Node {
    var root: Node {
        var current = self
        while let parentNode = current.parent {
            current = parentNode
        }
        return current
    }
    
    var level: Int {
        var count = 0
        var current = self
        while let parentNode = current.parent  {
            count+=1
            current = parentNode
        }
        return count
    }
    
    var leafs: [Node] {
        guard !isLeaf else {
            return [self]
        }
        return children.flatMap {
            return $0.leafs
        }
    }
    
    func getChildsForLevel(_ requiredLevel: Int) -> [Node] {
        guard requiredLevel > self.level else {
            return []
        }
        
        guard requiredLevel == self.level else {
            return [self]
        }
        
        return children.flatMap { $0.getChildsForLevel(requiredLevel) }
    }
}

extension Node: Sequence {
    func makeIterator() -> NodeIterator<Value> {
        return NodeIterator(current: self)
    }
}

struct NodeIterator<Value>: IteratorProtocol {
    var current: Node<Value>?

    mutating func next() -> Node<Value>? {
        defer { current = current?.parent }
        return current
    }
}
