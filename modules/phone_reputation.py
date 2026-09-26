"""
Phone number / caller reputation check ("is this call genuine?").

Mirrors the same three-tier pattern used for IP/domain reputation in
modules/blacklist.py, applied to phone numbers instead:
  1. Local growing SQLite-backed blacklist (BlacklistEntry, indicator_type='phone') —
     numbers an analyst/user has manually flagged from past cases.
  2. Bundled community-reported scam-number snapshot
     (ml_model/scam_numbers.csv) — a starter dataset in the same spirit as
     the PhishTank domain snapshot: numbers reported by the public as
     robocalls / bank-impersonation / "one-ring" fraud / etc. See
     README "Keeping the scam-number list fresh" for how to extend it;
     unlike PhishTank there's no single free authoritative feed for scam
     numbers, so this is meant to be grown from community reports (FTC
     DoNotCall complaint exports, user-submitted reports, etc.) rather
     than auto-refreshed from one source.
  3. Optional live API (IPQualityScore phone validation) if
     IPQUALITYSCORE_API_KEY is set. Fails gracefully with a clear status
     if not configured or unreachable — exactly like AbuseIPDB does for
     IPs in blacklist.py.

Numbers are normalized with the `phonenumbers` library when available
(handles spacing/punctuation/country-code variation so "+1 (555) 010-1234"
and "5550101234" match the same blacklist entry); falls back to a plain
digit-strip if the library isn't installed.
"""
import os
import csv
import re
import requests

try:
    import phonenumbers
    _HAS_PHONENUMBERS = True
except ImportError:  # pragma: no cover - exercised only when dependency missing
    _HAS_PHONENUMBERS = False

IPQUALITYSCORE_URL = "https://ipqualityscore.com/api/json/phone"

HERE = os.path.dirname(os.path.abspath(__file__))
SCAM_NUMBERS_PATH = os.path.join(HERE, '..', 'ml_model', 'scam_numbers.csv')

_scam_numbers = None


def normalize_number(raw_number, default_region='US'):
    """Returns (e164_or_digits, display, error). `display` is what to show
    the user back; the first value is what gets matched against the
    blacklist / scam-number snapshot so formatting differences don't cause
    false "not found" misses."""
    raw_number = (raw_number or '').strip()
    if not raw_number:
        return None, None, 'Enter a phone number.'

    if _HAS_PHONENUMBERS:
        try:
            parsed = phonenumbers.parse(raw_number, default_region)
            if not phonenumbers.is_possible_number(parsed):
                return None, raw_number, 'That does not look like a valid phone number.'
            e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            display = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            return e164, display, None
        except Exception:
            return None, raw_number, 'Could not parse that as a phone number.'

    digits = re.sub(r'\D', '', raw_number)
    if len(digits) < 7:
        return None, raw_number, 'That does not look like a valid phone number.'
    return digits, raw_number, None


def _load_scam_numbers():
    """Loads the bundled community-reported scam-number snapshot once per
    process. Keys are normalized to bare digits so lookups don't depend on
    which format the CSV row happened to be entered in."""
    global _scam_numbers
    if _scam_numbers is None:
        _scam_numbers = {}
        if os.path.exists(SCAM_NUMBERS_PATH):
            with open(SCAM_NUMBERS_PATH, newline='', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    number = re.sub(r'\D', '', row.get('number') or '')
                    if number:
                        _scam_numbers[number] = {
                            'category': row.get('category') or 'Reported scam number',
                            'report_count': row.get('report_count') or '1',
                            'last_reported': row.get('last_reported'),
                        }
    return _scam_numbers


def check_scam_number_list(normalized_number):
    """normalized_number should be E.164 (or bare digits fallback) as
    returned by normalize_number(). Matches on the trailing digits so a
    snapshot entered without a country code still matches a lookup that
    includes one, and vice versa."""
    db = _load_scam_numbers()
    if not normalized_number or not db:
        return {'status': 'checked' if db else 'unavailable', 'hit': None, 'dataset_size': len(db)}

    digits = re.sub(r'\D', '', normalized_number)
    info = db.get(digits)
    if not info:
        # Fall back to matching on the last 10 digits, so a snapshot row
        # missing/using a different leading country code still matches.
        for stored_digits, stored_info in db.items():
            if stored_digits[-10:] == digits[-10:] and len(digits) >= 10:
                info = stored_info
                break
    return {'status': 'checked', 'hit': info, 'dataset_size': len(db)}


def check_local_blacklist(normalized_number, db_session, BlacklistEntry):
    if not normalized_number:
        return []
    digits = re.sub(r'\D', '', normalized_number)
    entries = BlacklistEntry.query.filter_by(indicator_type='phone').all()
    return [
        {'indicator': e.indicator, 'reason': e.reason, 'added_on': str(e.added_on)}
        for e in entries
        if re.sub(r'\D', '', e.indicator)[-10:] == digits[-10:]
    ]


def check_ipqualityscore(normalized_number, timeout=4):
    api_key = os.environ.get('IPQUALITYSCORE_API_KEY')
    if not api_key:
        return {'status': 'not_configured',
                'message': 'Set IPQUALITYSCORE_API_KEY env var to enable live carrier/fraud-score lookups.'}
    if not normalized_number:
        return {'status': 'no_number'}
    try:
        resp = requests.get(
            f"{IPQUALITYSCORE_URL}/{api_key}/{normalized_number.lstrip('+')}",
            params={'country': 'US'},
            timeout=timeout,
        )
        data = resp.json()
        if not data.get('success', True) and data.get('message'):
            return {'status': 'unavailable', 'message': data['message']}
        return {
            'status': 'success',
            'valid': data.get('valid'),
            'fraud_score': data.get('fraud_score'),
            'recent_abuse': data.get('recent_abuse'),
            'spammer': data.get('spammer'),
            'line_type': data.get('line_type'),
            'carrier': data.get('carrier'),
            'risky': data.get('risky'),
        }
    except Exception as e:
        return {'status': 'unavailable', 'message': str(e)}


def compute_phone_score(local_hits, scam_list_result, api_result):
    """Same 0-100-ish additive scoring shape as compute_blacklist_score /
    risk_score.py's breakdown, so this slots into the platform's existing
    verdict language (LOW/MEDIUM/HIGH/CRITICAL) instead of inventing a
    parallel one."""
    score = 0
    reasons = []

    if local_hits:
        score += 40
        reasons.append(f"{len(local_hits)} match(es) in this platform's own reported-number list")

    hit = scam_list_result.get('hit')
    if hit:
        reasons.append(
            f"Reported by the community as: {hit['category']} "
            f"({hit.get('report_count', '1')} report(s), last {hit.get('last_reported') or 'unknown date'})"
        )
        score += 35

    if api_result.get('status') == 'success':
        fraud_score = api_result.get('fraud_score') or 0
        if api_result.get('recent_abuse'):
            score += 25
            reasons.append('Live lookup shows recent abuse reports against this number')
        elif fraud_score >= 75:
            score += 20
            reasons.append(f'Live fraud score {fraud_score}/100 — high risk')
        elif fraud_score >= 40:
            score += 10
            reasons.append(f'Live fraud score {fraud_score}/100 — moderate risk')
        if api_result.get('line_type') == 'Voip' and (hit or fraud_score >= 40):
            reasons.append('VoIP line combined with other risk signals — common for spoofed caller ID')

    score = min(score, 100)

    if score >= 60:
        severity = 'HIGH'
    elif score >= 30:
        severity = 'MEDIUM'
    elif score > 0:
        severity = 'LOW'
    else:
        severity = 'LOW'

    if not reasons:
        reasons.append('No matches in the local list, community reports, or live lookup. '
                        'Absence of a match is not a guarantee the number is safe — '
                        'caller ID can be spoofed regardless of reputation history.')

    return score, severity, reasons