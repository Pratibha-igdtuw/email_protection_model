"""
Auto-generated incident narrative.

Compiles everything the pipeline already computes for a case (analyzed
email) or a generic Evidence item -- classifier verdict, authentication
failures, attachment/document/image tamper flags, cluster/correlation
membership, chain-of-custody status -- into one readable paragraph.

This is the piece that turns "a case has a score, a timeline and a
correlation graph" into "reconstructing incidents from correlated
evidence" as a visible artifact on the page, rather than something an
analyst has to assemble by reading five separate sections.

Deliberately template-based prose over already-verified fields, not an
LLM call: every sentence here traces back to a value already stored on
the row (or already rendered elsewhere on the same page), so there's
nothing that could hallucinate, drift out of sync with the rest of the
UI, or need calibration against a dataset. That's also why it's safe to
demo live -- it can't say anything the rest of the case file doesn't
already say.
"""


def _join_and(items):
    items = [i for i in items if i]
    if not items:
        return ''
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _plural(n, word):
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _correlation_sentence(correlations, self_ref):
    """correlations: list of {'node': {...}, 'connections': [...], 'count': int}
    from modules/correlation_graph.py, already filtered to ones touching
    this case/evidence item (see app.py wiring)."""
    if not correlations:
        return None
    bits = []
    for c in correlations[:3]:
        other = c['count'] - 1
        bits.append(f"{c['node']['label']} (shared with {_plural(other, 'other item')})")
    return ("Cross-evidence correlation links this to other evidence in the workspace through "
            + _join_and(bits) + ", rather than this being an isolated, unconnected item.")


def build_case_narrative(case, incident_timeline, correlations=None):
    """
    case: a Case model instance (analyzed email).
    incident_timeline: the event list from modules/timeline.py's
        build_case_timeline() for this same case -- reused rather than
        recomputed, so the narrative can never disagree with the
        timeline widget on the same page about what happened.
    correlations: optional list of correlation dicts from
        modules/correlation_graph.py's find_correlations(), pre-filtered
        to ones touching this case.
    """
    sentences = []

    who = case.sender_from or "an unknown sender"
    domain_bit = f" ({case.sender_domain})" if case.sender_domain else ""
    sentences.append(
        f"This case was opened from an email received from {who}{domain_bit}, "
        f"scored {case.severity or 'Low'} severity ({round(case.combined_score or 0)}/100)."
    )

    events_by_title = {e['title']: e for e in incident_timeline}
    reasons = []
    if 'Authentication failure detected' in events_by_title:
        reasons.append(f"failed sender authentication ({events_by_title['Authentication failure detected']['detail']})")
    if case.ml_probability and case.ml_probability >= 50:
        reasons.append(f"was flagged by the content classifier as likely phishing ({round(case.ml_probability)}% probability)")
    if 'Attachment risk flagged' in events_by_title:
        reasons.append("carried a risky attachment")
    if 'Malicious / suspicious link flagged' in events_by_title:
        reasons.append("contained a suspicious or malicious link")

    if reasons:
        sentences.append("The evidence " + _join_and(reasons) + ".")
    else:
        sentences.append("No authentication failures, content red flags, or attachment/URL risk were found on this item.")

    cluster_events = [e for e in incident_timeline if e['icon'] == 'diagram-project']
    if cluster_events:
        bits = [f"{e['detail']}" for e in cluster_events]
        sentences.append(
            "It shares infrastructure with other cases in this workspace ("
            + _join_and(bits) + "), suggesting coordinated or repeat activity rather than an isolated incident."
        )

    corr_sentence = _correlation_sentence(correlations, case.case_ref)
    if corr_sentence:
        sentences.append(corr_sentence)

    if case.evidence_sha256:
        sentences.append(
            f"The evidence was hashed (SHA-256 {case.evidence_sha256[:16]}\u2026) and committed to the "
            f"append-only blockchain ledger at ingestion, so its integrity from that point forward is "
            f"independently verifiable."
        )

    return " ".join(sentences)


_EVIDENCE_TYPE_LABELS = {
    'email': 'an email',
    'sms_export': 'an SMS export',
    'chat_log': 'a chat log',
    'image': 'an image',
    'document': 'a document',
    'file': 'a file',
}


def build_evidence_narrative(item, metadata, correlations=None):
    """
    item: an Evidence model instance.
    metadata: the parsed metadata dict already loaded for this item
        (json.loads(item.metadata_json)) -- reused rather than reparsed.
    correlations: optional list of correlation dicts from
        modules/correlation_graph.py's find_correlations(), pre-filtered
        to ones touching this evidence item.
    """
    sentences = []
    metadata = metadata or {}

    kind = _EVIDENCE_TYPE_LABELS.get(item.evidence_type, 'a piece of evidence')
    name_bit = f" (\u201c{item.original_filename}\u201d)" if item.original_filename else ""
    sentences.append(f"This item was ingested as {kind}{name_bit}.")

    flags = metadata.get('flags')
    if flags:
        sentences.append(
            "Forensic analysis flagged " + _plural(len(flags), 'issue') + ": " + "; ".join(flags) + "."
        )
    elif item.evidence_type in ('image', 'document'):
        sentences.append("Forensic analysis found no tampering signals on this item.")

    if metadata.get('detected_phone_number_count'):
        sentences.append(
            f"The content references {_plural(metadata['detected_phone_number_count'], 'distinct phone number')}."
        )

    corr_sentence = _correlation_sentence(correlations, item.evidence_ref)
    if corr_sentence:
        sentences.append(corr_sentence)

    if item.sha256:
        sentences.append(
            f"The evidence was hashed (SHA-256 {item.sha256[:16]}\u2026) and committed to the append-only "
            f"blockchain ledger at ingestion, so its integrity from that point forward is independently "
            f"verifiable."
        )

    if item.linked_case_ref:
        sentences.append(f"It is linked to case {item.linked_case_ref}.")

    return " ".join(sentences)