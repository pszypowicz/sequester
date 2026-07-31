import Foundation
import SequesterCore

/// Destination records arranged by their binding chains: records sharing a
/// first hop share a branch, so multi-hop forwarding renders as nesting.
/// Nodes merge on host key fingerprint, which lets a host someone logs
/// into directly and forwards through appear once, carrying both its own
/// record and children.
struct DestinationTree {

    struct Node: Identifiable {
        let id: String
        let fingerprint: String
        let algorithm: String
        var record: DestinationRecord?
        var children: [Node]
        var latestActivity: Date
    }

    static func build(_ records: [DestinationRecord]) -> [Node] {
        var roots: [Node] = []
        for record in records {
            insert(record, hops: record.hops[...], into: &roots, path: "")
        }
        sort(&roots)
        return roots
    }

    private static func insert(_ record: DestinationRecord, hops: ArraySlice<ChainHop>,
                               into nodes: inout [Node], path: String) {
        guard let hop = hops.first else { return }
        let id = "\(path)/\(hop.fingerprint)"
        let index = nodes.firstIndex { $0.fingerprint == hop.fingerprint } ?? {
            nodes.append(Node(
                id: id, fingerprint: hop.fingerprint, algorithm: hop.algorithm,
                record: nil, children: [], latestActivity: .distantPast
            ))
            return nodes.count - 1
        }()
        nodes[index].latestActivity = max(nodes[index].latestActivity, record.lastUsed)
        if hops.count == 1 {
            nodes[index].record = record
        } else {
            insert(record, hops: hops.dropFirst(), into: &nodes[index].children, path: id)
        }
    }

    private static func sort(_ nodes: inout [Node]) {
        nodes.sort { $0.latestActivity > $1.latestActivity }
        for index in nodes.indices {
            sort(&nodes[index].children)
        }
    }
}
