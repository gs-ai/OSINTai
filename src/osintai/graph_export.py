import os
import time
from typing import Dict, List, Any
from .storage import append_jsonl

def _ts() -> float:
    return time.time()

def emit_node(path: str, node: Dict[str, Any]) -> None:
    append_jsonl(path, node)

def emit_edge(path: str, edge: Dict[str, Any]) -> None:
    append_jsonl(path, edge)

def export_graph(run_dir: str, pages: List[Dict[str, Any]], indicators_by_url: Dict[str, Dict[str, Any]]):
    """
    Writes:
      graph_nodes.jsonl
      graph_edges.jsonl

    Nodes:
      - page
      - domain
      - ip
      - email
      - phone
      - crypto
      - handle
    Edges:
      - page -> domain
      - page -> indicator
    """
    nodes_path = os.path.join(run_dir, "graph_nodes.jsonl")
    edges_path = os.path.join(run_dir, "graph_edges.jsonl")

    seen_nodes = set()

    def ensure_node(node_id: str, ntype: str, label: str, props: Dict[str, Any]):
        key = (node_id, ntype)
        if key in seen_nodes:
            return
        seen_nodes.add(key)
        emit_node(nodes_path, {
            "id": node_id,
            "type": ntype,
            "label": label,
            "props": props,
            "ts": _ts()
        })

    def link(src: str, dst: str, etype: str, props: Dict[str, Any]):
        emit_edge(edges_path, {
            "src": src,
            "dst": dst,
            "type": etype,
            "props": props,
            "ts": _ts()
        })

    for p in pages:
        url = p.get("url")
        if not url:
            continue
        page_id = "page:" + url
        ensure_node(page_id, "page", url, {
            "title": p.get("title", ""),
            "score": p.get("score", 0),
            "summary": p.get("summary", "")
        })

        ind = indicators_by_url.get(url, {}) or {}
        # domains
        for d in ind.get("domains", [])[:200]:
            did = "domain:" + d
            ensure_node(did, "domain", d, {})
            link(page_id, did, "mentions_domain", {})

        # IP addresses
        for ip in ind.get("ip_addresses", [])[:200]:
            iid = "ip:" + ip
            ensure_node(iid, "ip", ip, {})
            link(page_id, iid, "mentions_ip", {})

        # emails
        for e in ind.get("emails", [])[:200]:
            eid = "email:" + e.lower()
            ensure_node(eid, "email", e.lower(), {})
            link(page_id, eid, "mentions_email", {})

        # phones
        for ph in ind.get("phones", [])[:200]:
            pid = "phone:" + ph
            ensure_node(pid, "phone", ph, {})
            link(page_id, pid, "mentions_phone", {})

        # crypto
        for b in ind.get("btc_addresses", [])[:200]:
            bid = "btc:" + b
            ensure_node(bid, "crypto_btc", b, {})
            link(page_id, bid, "mentions_btc", {})
        for e in ind.get("eth_addresses", [])[:200]:
            eid = "eth:" + e
            ensure_node(eid, "crypto_eth", e, {})
            link(page_id, eid, "mentions_eth", {})

        # handles
        for h in ind.get("social_handles", [])[:200]:
            hid = "handle:" + h.lower()
            ensure_node(hid, "handle", h.lower(), {})
            link(page_id, hid, "mentions_handle", {})
