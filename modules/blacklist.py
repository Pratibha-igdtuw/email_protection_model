"""
Blacklist / reputation check for sender IP, sender domain, and URLs found
in the email body. Three tiers:
  1. Local growing SQLite-backed blacklist (populated by analysts / previous cases).
  2. PhishTank-verified phishing domain snapshot, bundled in
     ml_model/phishtank_domains.csv (see ml_model/build_training_dataset.py's
     sibling fetch step / README for how to refresh it). PhishTank publishes
     confirmed, community-verified phishing URLs — this checks the sender
     domain and any URLs in the message against that list directly, which is
     the correct use of PhishTank data (it's a URL/domain reputation feed,
     not email text, so it doesn't belong in the content classifier's
     training set).
  3. Optional external API (AbuseIPDB) if an API key is configured via env var
     ABUSEIPDB_API_KEY. Fails gracefully with a clear status if not configured
     or unreachable.
"""
import os
import re
import csv
import json
import requests
from datetime import datetime, timezone

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

HERE = os.path.dirname(os.path.abspath(__file__))
PHISHTANK_PATH = os.path.join(HERE, '..', 'ml_model', 'phishtank_domains.csv')
PHISHTANK_METADATA_PATH = os.path.join(HERE, '..', 'ml_model', 'phishtank_metadata.json')

# How old the bundled snapshot can get before we start warning analysts that
# it's stale. PhishTank has no free live-lookup API, so this is a snapshot by
# necessity -- see ml_model/refresh_phishtank.py to pull a fresh one, and the
# README section "Keeping PhishTank data fresh" for a scheduling recipe.
PHISHTANK_STALE_AFTER_DAYS = 14

_phishtank_domains = None
_phishtank_metadata = None


def _load_phishtank_metadata():
    global _phishtank_metadata
    if _phishtank_metadata is None:
        _phishtank_metadata = {}
        if os.path.exists(PHISHTANK_METADATA_PATH):
            try:
                with open(PHISHTANK_METADATA_PATH, encoding='utf-8') as f:
                    _phishtank_metadata = json.load(f)
            except (json.JSONDecodeError, OSError):
                _phishtank_metadata = {}
    return _phishtank_metadata


def get_phishtank_freshness():
    """Returns {'last_refreshed_at': iso_str_or_None, 'age_days': float_or_None,
    'stale': bool}. Used to warn analysts in the UI/PDF report and to log a
    startup warning, instead of silently serving an aging snapshot."""
    meta = _load_phishtank_metadata()
    last_refreshed_at = meta.get('last_refreshed_at')
    if not last_refreshed_at:
        return {'last_refreshed_at': None, 'age_days': None, 'stale': True}
    try:
        refreshed_dt = datetime.fromisoformat(last_refreshed_at.replace('Z', '+00:00'))
        age_days = (datetime.now(timezone.utc) - refreshed_dt).total_seconds() / 86400
        return {
            'last_refreshed_at': last_refreshed_at,
            'age_days': round(age_days, 1),
            'stale': age_days > PHISHTANK_STALE_AFTER_DAYS,
        }
    except ValueError:
        return {'last_refreshed_at': last_refreshed_at, 'age_days': None, 'stale': True}


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


def _load_phishtank_domains():
    """Loads the bundled PhishTank-verified domain snapshot once per process."""
    global _phishtank_domains
    if _phishtank_domains is None:
        _phishtank_domains = {}
        if os.path.exists(PHISHTANK_PATH):
            with open(PHISHTANK_PATH, newline='', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    d = (row.get('domain') or '').strip().lower()
                    if d:
                        _phishtank_domains[d] = {
                            'target': row.get('target') or 'Other',
                            'verified_time': row.get('verified_time'),
                        }
    return _phishtank_domains


def check_phishtank(sender_domain, urls):
    """Cross-references the sender domain and any URL hosts found in the
    email body against the bundled PhishTank-verified phishing domain
    snapshot. Returns every matching domain with the brand it was
    impersonating and when PhishTank verified it."""
    domains_db = _load_phishtank_domains()
    freshness = get_phishtank_freshness()
    if not domains_db:
        return {'status': 'unavailable', 'hits': [], 'dataset_size': 0, **freshness}

    candidates = set()
    if sender_domain:
        candidates.add(sender_domain.strip().lower())
    for u in urls or []:
        m = re.search(r'https?://([^/]+)', u)
        if m:
            candidates.add(m.group(1).split(':')[0].lower())

    hits = []
    for domain in candidates:
        info = domains_db.get(domain)
        if info:
            hits.append({'domain': domain, 'target': info['target'], 'verified_time': info['verified_time']})

    return {'status': 'checked', 'hits': hits, 'dataset_size': len(domains_db), **freshness}


def compute_blacklist_score(local_hits, abuseipdb_result, phishtank_result=None):
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
    if phishtank_result and phishtank_result.get('hits'):
        score += 20
        for h in phishtank_result['hits']:
            reasons.append(
                f"Domain '{h['domain']}' matches a PhishTank-verified phishing domain "
                f"(impersonating: {h['target']}, verified {h['verified_time']})"
            )
    return min(score, 20), reasons
