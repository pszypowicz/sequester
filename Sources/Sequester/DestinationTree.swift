import Foundation
import SequesterCore

/// Arranges destination records into a route tree. The forwarding hops (all
/// hops except the last) form the branches; the final hop is the
/// destination reached at that point, shown as a leaf under its route.
///
/// A host used directly is a destination at the root, distinct from the
/// same host used as a forwarding hop, so a direct connection is never
/// hidden inside a forwarding branch and collapsing a branch never conceals
/// it.
struct DestinationTree {

    struct Node: Identifiable {
        /// The route path (forwarding hops) from the root to this node.
        let hops: [BindingHop]
        let fingerprint: String
        let algorithm: String
        /// Records reached via exactly this route (binding chain == hops + [dest]).
        var destinations: [DestinationRecord]
        /// Longer routes that continue through this node.
        var children: [Node]
        var latestActivity: Date

        var id: String { "route:" + DestinationRecord.bindingChainID(hops) }
    }

    /// Records reached directly, with no forwarding hop before them.
    let rootDestinations: [DestinationRecord]
    let rootRoutes: [Node]

    static func build(_ records: [DestinationRecord]) -> DestinationTree {
        var rootDestinations: [DestinationRecord] = []
        var roots: [Node] = []
        for record in records {
            let route = Array(record.hops.dropLast())
            if route.isEmpty {
                rootDestinations.append(record)
            } else {
                insert(record, route: route[...], prefix: [], into: &roots)
            }
        }
        sort(&roots)
        return DestinationTree(
            rootDestinations: rootDestinations.sorted { $0.lastUsed > $1.lastUsed },
            rootRoutes: roots
        )
    }

    private static func insert(_ record: DestinationRecord, route: ArraySlice<BindingHop>,
                               prefix: [BindingHop], into nodes: inout [Node]) {
        guard let hop = route.first else { return }
        let hops = prefix + [hop]
        let index = nodes.firstIndex { $0.fingerprint == hop.fingerprint } ?? {
            nodes.append(Node(hops: hops, fingerprint: hop.fingerprint, algorithm: hop.algorithm,
                              destinations: [], children: [], latestActivity: .distantPast))
            return nodes.count - 1
        }()
        nodes[index].latestActivity = max(nodes[index].latestActivity, record.lastUsed)
        if route.count == 1 {
            nodes[index].destinations.append(record)
        } else {
            insert(record, route: route.dropFirst(), prefix: hops, into: &nodes[index].children)
        }
    }

    private static func sort(_ nodes: inout [Node]) {
        nodes.sort { $0.latestActivity > $1.latestActivity }
        for i in nodes.indices {
            nodes[i].destinations.sort { $0.lastUsed > $1.lastUsed }
            sort(&nodes[i].children)
        }
    }
}

/// One line in the flattened destination view: either a route hop
/// (expandable) or a destination leaf, tagged with its indentation depth.
struct DestinationRow: Identifiable {
    let id: String
    let depth: Int
    let kind: Kind

    enum Kind {
        case route(DestinationTree.Node)
        case destination(DestinationRecord)
    }
}

extension DestinationTree {

    /// Flattens the tree into display rows, honoring the collapsed set.
    /// Destinations at a level come before the deeper routes at that level.
    func rows(collapsed: Set<String>) -> [DestinationRow] {
        var rows: [DestinationRow] = []
        for destination in rootDestinations {
            rows.append(DestinationRow(id: destination.id, depth: 0, kind: .destination(destination)))
        }
        for node in rootRoutes {
            append(node, depth: 0, collapsed: collapsed, into: &rows)
        }
        return rows
    }

    private func append(_ node: Node, depth: Int, collapsed: Set<String>, into rows: inout [DestinationRow]) {
        rows.append(DestinationRow(id: node.id, depth: depth, kind: .route(node)))
        guard !collapsed.contains(node.id) else { return }
        for destination in node.destinations {
            rows.append(DestinationRow(id: destination.id, depth: depth + 1, kind: .destination(destination)))
        }
        for child in node.children {
            append(child, depth: depth + 1, collapsed: collapsed, into: &rows)
        }
    }
}
