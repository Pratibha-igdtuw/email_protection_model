"""
WHOIS lookup for sending domain - registrar, creation date.
Newly registered domains (<30 days old) are a strong red flag for phishing.
"""
from datetime import datetime, timezone

try:
    import whois as pywhois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def lookup_domain(domain):
    if not domain:
        return {'status': 'no_domain'}
    if not WHOIS_AVAILABLE:
        return {'status': 'unavailable', 'message': 'python-whois not installed', 'domain': domain}
    try:
        w = pywhois.whois(domain)
        creation_date = _first(w.creation_date)
        expiration_date = _first(w.expiration_date)

        domain_age_days = None
        is_newly_registered = False
        if isinstance(creation_date, datetime):
            now = datetime.now(timezone.utc) if creation_date.tzinfo else datetime.now()
            domain_age_days = (now - creation_date).days
            is_newly_registered = domain_age_days is not None and domain_age_days < 30

        return {
            'status': 'success',
            'domain': domain,
            'registrar': _first(w.registrar),
            'creation_date': str(creation_date) if creation_date else None,
            'expiration_date': str(expiration_date) if expiration_date else None,
            'domain_age_days': domain_age_days,
            'is_newly_registered': is_newly_registered,
            'name_servers': w.name_servers if isinstance(w.name_servers, list) else ([w.name_servers] if w.name_servers else []),
            'org': _first(getattr(w, 'org', None)),
            'country': _first(getattr(w, 'country', None)),
        }
    except Exception as e:
        return {'status': 'failed', 'message': str(e), 'domain': domain}
