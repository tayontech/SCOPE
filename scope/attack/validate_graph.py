from __future__ import annotations

from typing import Any


def graph_edge_ids(graph: dict[str, Any]) -> set[str]:
    return set(graph_edges_by_id(graph))


def graph_edges_by_id(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    edges = graph.get("edges", [])
    if not isinstance(edges, list):
        return {}
    return {
        edge["id"]: edge
        for edge in edges
        if isinstance(edge, dict) and isinstance(edge.get("id"), str)
    }


def graph_nodes_by_id(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    nodes = graph.get("nodes", [])
    if not isinstance(nodes, list):
        return {}
    return {
        node["id"]: node
        for node in nodes
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    }


def graph_node_ids(graph: dict[str, Any]) -> set[str]:
    nodes = graph.get("nodes", [])
    if not isinstance(nodes, list):
        return set()
    return {
        node["id"]
        for node in nodes
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    }
