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
        /// The chain from the root down to and including this node, which
        /// is the prefix a branch rule on this node applies to.
        let hops: [ChainHop]
        var record: DestinationRecord?
        var children: [Node]
        var latestActivity: Date
    }

    static func build(_ records: [DestinationRecord]) -> [Node] {
        var roots: [Node] = []
        for record in records {
            insert(record, remaining: record.hops[...], prefix: [], into: &roots)
        }
        sort(&roots)
        return roots
    }

    private static func insert(_ record: DestinationRecord, remaining: ArraySlice<ChainHop>,
                               prefix: [ChainHop], into nodes: inout [Node]) {
        guard let hop = remaining.first else { return }
        let hops = prefix + [hop]
        let index = nodes.firstIndex { $0.fingerprint == hop.fingerprint } ?? {
            nodes.append(Node(
                id: DestinationRecord.chainID(hops),
                fingerprint: hop.fingerprint, algorithm: hop.algorithm, hops: hops,
                record: nil, children: [], latestActivity: .distantPast
            ))
            return nodes.count - 1
        }()
        nodes[index].latestActivity = max(nodes[index].latestActivity, record.lastUsed)
        if remaining.count == 1 {
            nodes[index].record = record
        } else {
            insert(record, remaining: remaining.dropFirst(), prefix: hops, into: &nodes[index].children)
        }
    }

    private static func sort(_ nodes: inout [Node]) {
        nodes.sort { $0.latestActivity > $1.latestActivity }
        for index in nodes.indices {
            sort(&nodes[index].children)
        }
    }
}
