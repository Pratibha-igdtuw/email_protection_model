"""
USP 2 (part): Geolocation clustering to detect coordinated/repeat-offender
campaigns. Groups historical cases by originating IP, ASN, and sender
domain so an analyst can see when multiple "different" phishing emails
actually trace back to the same infrastructure.
"""
from collections import defaultdict


def build_clusters(cases):
    """
    `cases` is a list of Case model instances (or dicts with the same keys).
    Returns a list of cluster dicts, each representing a group of >=2 cases
    sharing the same IP, ASN, or sender domain — sorted by cluster size
    (biggest / most repeated infrastructure first).
    """
    by_ip = defaultdict(list)
    by_asn = defaultdict(list)
    by_domain = defaultdict(list)

    for c in cases:
        ip = getattr(c, 'originating_ip', None)
        asn = getattr(c, 'asn', None)
        domain = getattr(c, 'sender_domain', None)
        if ip:
            by_ip[ip].append(c)
        if asn:
            by_asn[asn].append(c)
        if domain:
            by_domain[domain].append(c)

    clusters = []

    for ip, group in by_ip.items():
        if len(group) >= 2:
            clusters.append({
                'cluster_type': 'Same Originating IP',
                'key': ip,
                'case_count': len(group),
                'severities': [g.severity for g in group],
                'cases': group,
                'max_score': max((g.combined_score or 0) for g in group),
            })

    for asn, group in by_asn.items():
        if len(group) >= 2:
            # avoid duplicate reporting when the IP cluster already covers it fully
            distinct_ips = set(getattr(g, 'originating_ip', None) for g in group)
            if len(distinct_ips) > 1:  # only interesting if it spans multiple IPs
                clusters.append({
                    'cluster_type': 'Same Hosting / ASN',
                    'key': asn,
                    'case_count': len(group),
                    'severities': [g.severity for g in group],
                    'cases': group,
                    'max_score': max((g.combined_score or 0) for g in group),
                })

    for domain, group in by_domain.items():
        if len(group) >= 2:
            clusters.append({
                'cluster_type': 'Same Sender Domain',
                'key': domain,
                'case_count': len(group),
                'severities': [g.severity for g in group],
                'cases': group,
                'max_score': max((g.combined_score or 0) for g in group),
            })

    clusters.sort(key=lambda c: (c['case_count'], c['max_score']), reverse=True)
    return clusters


def repeat_offender_summary(cases):
    """Quick stats block for the map/dashboard: how many distinct malicious
    IPs/domains have sent more than once."""
    clusters = build_clusters(cases)
    repeat_ip_clusters = [c for c in clusters if c['cluster_type'] == 'Same Originating IP']
    return {
        'total_clusters': len(clusters),
        'repeat_offender_ips': len(repeat_ip_clusters),
        'largest_campaign_size': max([c['case_count'] for c in clusters], default=0),
    }
