"""
Blacklist / reputation check for sender IP and domain.
Two tiers:
  1. Local growing SQLite-backed blacklist (populated by analysts / previous cases).
  2. Optional external API (AbuseIPDB) if an API key is configured via env var
     ABUSEIPDB_API_KEY. Fails gracefully with a clear status if not configured
     or unreachable, matching the CleanTalk "Block Lists" equivalent described
     in the spec.
"""
import os
import requests

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def check_local_blacklist(ip_address, domain, db_session, BlacklistEntry):
    entries = []
    if ip_address:
        entries += BlacklistEntry.query.filter_by(indicator=ip_address, indicator_type='ip').all()
    if domain:
        entries += BlacklistEntry.query.filter_by(indicator=domain, indicator_type='domain').all()
    return [{'indicator': e.indicator, 'type': e.indicator_type, 'reason': e.reason,
             'added_on': str(e.added_on)} for e in entries]


def check_abuseipdb(ip_address, timeout=4):
    api_key = os.environ.get('ABUSEIPDB_API_KEY')
    if not api_key:
        return {'status': 'not_configured',
                'message': 'Set ABUSEIPDB_API_KEY env var to enable live reputation checks.'}
    if not ip_address:
        return {'status': 'no_ip'}
    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={'Key': api_key, 'Accept': 'application/json'},
            params={'ipAddress': ip_address, 'maxAgeInDays': 90},
            timeout=timeout,
        )
        data = resp.json().get('data', {})
        return {
            'status': 'success',
            'abuse_confidence_score': data.get('abuseConfidenceScore'),
            'total_reports': data.get('totalReports'),
            'is_public': data.get('isPublic'),
            'usage_type': data.get('usageType'),
            'is_whitelisted': data.get('isWhitelisted'),
        }
    except Exception as e:
        return {'status': 'unavailable', 'message': str(e)}


def compute_blacklist_score(local_hits, abuseipdb_result):
    score = 0
    reasons = []
    if local_hits:
        score += 20
        reasons.append(f"{len(local_hits)} local blacklist match(es)")
    if abuseipdb_result.get('status') == 'success':
        conf = abuseipdb_result.get('abuse_confidence_score') or 0
        if conf >= 75:
            score += 20
            reasons.append(f"AbuseIPDB confidence score {conf}% — high abuse likelihood")
        elif conf >= 25:
            score += 10
            reasons.append(f"AbuseIPDB confidence score {conf}% — moderate abuse history")
    return min(score, 20), reasons
