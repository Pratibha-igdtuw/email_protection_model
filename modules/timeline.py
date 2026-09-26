"""
Incident reconstruction timeline. Turns the flat fields already stored
on a Case, plus a live clustering lookup against the analyst's other
cases, into an ordered "what happened" narrative: received -> auth
failure detected -> content/attachment/URL flagged -> clustered with
N other cases -- rather than just a table of scores.

Reuses modules/clustering.py for the "clustered with N other cases"
step instead of re-deriving infrastructure-matching logic.
"""
from modules import clustering


def _auth_failures(case):
    fails = []
    for label, value in (('SPF', case.spf_result), ('DKIM', case.dkim_result),
                          ('DMARC', case.dmarc_result)):
        if value and value.strip().lower() not in ('pass', ''):
            fails.append(f"{label}={value}")
    return fails


def build_case_timeline(case, sibling_cases=None):
    """
    `sibling_cases` lets the caller pass in a list of the same owner's
    other cases it may have already fetched (e.g. the dashboard),
    avoiding a redundant query. If omitted, this queries for them.
    """
    events = []

    events.append({
        'icon': 'inbox',
        'title': 'Evidence received',
        'time': case.created_at,
        'detail': (f"From {case.sender_from}" if case.sender_from else 'Sender unknown')
                   + (f" ({case.sender_domain})" if case.sender_domain else ''),
    })

    auth_fails = _auth_failures(case)
    if auth_fails:
        events.append({
            'icon': 'key',
            'title': 'Authentication failure detected',
            'time': case.created_at,
            'detail': ', '.join(auth_fails),
        })

    if case.ml_probability is not None and case.ml_probability >= 50:
        events.append({
            'icon': 'robot',
            'title': 'Content classifier flagged as likely phishing',
            'time': case.created_at,
            'detail': f"ML probability: {case.ml_probability}%",
        })

    if getattr(case, 'attachment_flags', None):
        events.append({
            'icon': 'paperclip',
            'title': 'Attachment risk flagged',
            'time': case.created_at,
            'detail': case.attachment_flags,
        })

    if getattr(case, 'url_flags', None):
        events.append({
            'icon': 'link',
            'title': 'Malicious / suspicious link flagged',
            'time': case.created_at,
            'detail': case.url_flags,
        })

    if sibling_cases is None:
        from models import Case
        sibling_cases = (Case.query.filter_by(owner_id=case.owner_id).all()
                          if case.owner_id is not None else [case])

    clusters = clustering.build_clusters(sibling_cases)
    seen_cluster_types = set()
    for cl in clusters:
        if case.case_ref not in {getattr(sc, 'case_ref', None) for sc in cl['cases']}:
            continue
        if cl['cluster_type'] in seen_cluster_types:
            continue  # one timeline entry per infrastructure dimension is plenty
        seen_cluster_types.add(cl['cluster_type'])
        other_count = cl['case_count'] - 1
        events.append({
            'icon': 'diagram-project',
            'title': f"Clustered with {other_count} other case(s)",
            'time': case.created_at,
            'detail': f"{cl['cluster_type']}: {cl['key']}",
        })

    if case.hash_generated_at:
        events.append({
            'icon': 'shield-halved',
            'title': 'Evidence hashed and committed to blockchain ledger',
            'time': case.hash_generated_at,
            'detail': f"SHA-256 {case.evidence_sha256[:16]}…" if case.evidence_sha256 else None,
        })

    if case.report_path:
        events.append({
            'icon': 'file-pdf',
            'title': 'Forensic PDF report generated',
            'time': case.created_at,
            'detail': None,
        })

    return events