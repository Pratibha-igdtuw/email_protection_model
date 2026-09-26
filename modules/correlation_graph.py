"""
Module: Cross-evidence correlation graph

USP: every other dashboard view here (clusters, anomalies, map) looks at
ONE data source at a time -- analyzed-email Cases only. Real incidents
span sources: a phishing email, a follow-up scam call, a screenshot of a
fake SMS, a forged PDF invoice can all point back to the same
infrastructure. This module builds a single entity-relationship graph
across BOTH Cases (analyzed emails) and Evidence (the generic multi-source
ingestion pipeline in evidence_ingest.py) so a shared sender address,
domain, originating IP, or phone number becomes a visible pivot point
instead of three separate, disconnected records an analyst has to notice
by hand.

Node types: 'case' (an analyzed email), 'file' (an ingested evidence
item), 'sender' (an email address), 'domain', 'ip', 'phone'. Correlation
is implicit in the graph structure itself -- entity nodes (sender/domain/
ip/phone) are deduplicated by their normalized value, so the same domain
appearing in two different cases, or the same phone number appearing in
two different evidence uploads, naturally becomes one node with multiple
edges into it rather than two separate mentions. find_correlations() then
just walks the graph for entity nodes with more than one distinct
case/file neighbor and ranks them -- that's the whole "correlation"
algorithm; nothing fuzzy or ML-based, just shared-value graph merging.

Kept free of Flask/DB imports (like clustering.py) -- callers pass in
already-queried Case/Evidence rows (or dicts with the same attributes) and
render the result themselves.
"""
import json
from collections import defaultdict

# Cap how many phone-number nodes one evidence item can contribute -- a
# large chat export could otherwise flood the graph with one-off numbers
# that were never meant to be forensic pivots. evidence_ingest.py already
# caps detected_phone_numbers at 20 per item; this is a second, graph-level
# cap in case that ever changes independently.
MAX_PHONE_NODES_PER_EVIDENCE = 20


def _add_node(nodes, node_id, label, node_type, **extra):
    if node_id not in nodes:
        node = {'id': node_id, 'label': label, 'type': node_type}
        node.update(extra)
        nodes[node_id] = node
    return nodes[node_id]


def _add_edge(edges_seen, edges, source, target, relation):
    key = (source, target, relation)
    if key in edges_seen:
        return
    edges_seen.add(key)
    edges.append({'source': source, 'target': target, 'relation': relation})


def build_graph(cases, evidence_items):
    """
    cases: iterable of Case model instances (or dicts with the same keys):
        case_ref, subject, sender_from, sender_domain, originating_ip,
        severity, combined_score.
    evidence_items: iterable of Evidence model instances (or dicts):
        evidence_ref, original_filename, evidence_type, linked_case_ref,
        metadata_json.

    Returns {'nodes': [...], 'edges': [...]}. Node/edge dicts are plain
    JSON-serializable data -- no model instances -- so this can go
    straight into a template via |tojson.
    """
    nodes = {}
    edges = []
    edges_seen = set()

    case_refs_present = set()

    for c in cases:
        case_ref = getattr(c, 'case_ref', None) if not isinstance(c, dict) else c.get('case_ref')
        if not case_ref:
            continue
        case_refs_present.add(case_ref)
        case_id = f"case:{case_ref}"
        subject = getattr(c, 'subject', None) if not isinstance(c, dict) else c.get('subject')
        severity = getattr(c, 'severity', None) if not isinstance(c, dict) else c.get('severity')
        score = getattr(c, 'combined_score', None) if not isinstance(c, dict) else c.get('combined_score')
        sender_from = getattr(c, 'sender_from', None) if not isinstance(c, dict) else c.get('sender_from')
        sender_domain = getattr(c, 'sender_domain', None) if not isinstance(c, dict) else c.get('sender_domain')
        originating_ip = getattr(c, 'originating_ip', None) if not isinstance(c, dict) else c.get('originating_ip')

        _add_node(nodes, case_id, case_ref, 'case', ref=case_ref,
                  subtitle=(subject or '')[:80], severity=severity, score=score)

        if sender_from:
            sender_id = f"sender:{sender_from.strip().lower()}"
            _add_node(nodes, sender_id, sender_from.strip(), 'sender')
            _add_edge(edges_seen, edges, case_id, sender_id, 'sent by')

        if sender_domain:
            domain_id = f"domain:{sender_domain.strip().lower()}"
            _add_node(nodes, domain_id, sender_domain.strip(), 'domain')
            _add_edge(edges_seen, edges, case_id, domain_id, 'from domain')
            if sender_from:
                sender_id = f"sender:{sender_from.strip().lower()}"
                _add_edge(edges_seen, edges, sender_id, domain_id, 'domain of')

        if originating_ip:
            ip_id = f"ip:{originating_ip.strip()}"
            _add_node(nodes, ip_id, originating_ip.strip(), 'ip')
            _add_edge(edges_seen, edges, case_id, ip_id, 'originated from')
            if sender_domain:
                domain_id = f"domain:{sender_domain.strip().lower()}"
                _add_edge(edges_seen, edges, domain_id, ip_id, 'resolved to')

    for e in evidence_items:
        evidence_ref = getattr(e, 'evidence_ref', None) if not isinstance(e, dict) else e.get('evidence_ref')
        if not evidence_ref:
            continue
        filename = getattr(e, 'original_filename', None) if not isinstance(e, dict) else e.get('original_filename')
        evidence_type = getattr(e, 'evidence_type', None) if not isinstance(e, dict) else e.get('evidence_type')
        linked_case_ref = getattr(e, 'linked_case_ref', None) if not isinstance(e, dict) else e.get('linked_case_ref')
        metadata_json = getattr(e, 'metadata_json', None) if not isinstance(e, dict) else e.get('metadata_json')

        file_id = f"file:{evidence_ref}"
        _add_node(nodes, file_id, filename or evidence_ref, 'file',
                  ref=evidence_ref, subtitle=evidence_type)

        if linked_case_ref and linked_case_ref in case_refs_present:
            _add_edge(edges_seen, edges, file_id, f"case:{linked_case_ref}", 'linked to')

        try:
            meta = json.loads(metadata_json) if metadata_json else {}
        except (ValueError, TypeError):
            meta = {}

        for phone in (meta.get('detected_phone_numbers') or [])[:MAX_PHONE_NODES_PER_EVIDENCE]:
            phone_id = f"phone:{phone}"
            _add_node(nodes, phone_id, phone, 'phone')
            _add_edge(edges_seen, edges, file_id, phone_id, 'mentions')

    return {'nodes': list(nodes.values()), 'edges': edges}


def find_correlations(graph):
    """
    Walks the built graph for entity nodes (sender/domain/ip/phone) that
    connect to more than one distinct case/file node -- i.e. a value that
    shows up in more than one piece of evidence, which is exactly the
    "different-looking sources are actually connected" signal this
    feature exists to surface.

    Returns a list of {'node': {...}, 'connections': [case/file node
    dicts], 'count': int}, sorted by connection count descending.
    """
    nodes_by_id = {n['id']: n for n in graph['nodes']}
    neighbors = defaultdict(set)
    for edge in graph['edges']:
        neighbors[edge['source']].add(edge['target'])
        neighbors[edge['target']].add(edge['source'])

    correlations = []
    for node in graph['nodes']:
        if node['type'] not in ('sender', 'domain', 'ip', 'phone'):
            continue
        connected_sources = [
            nodes_by_id[nid] for nid in neighbors.get(node['id'], ())
            if nid in nodes_by_id and nodes_by_id[nid]['type'] in ('case', 'file')
        ]
        if len(connected_sources) >= 2:
            correlations.append({
                'node': node,
                'connections': connected_sources,
                'count': len(connected_sources),
            })

    correlations.sort(key=lambda c: c['count'], reverse=True)
    return correlations