"""
WHOIS lookup for sending domain - registrar, creation date.
Newly registered domains (<30 days old) are a strong red flag for phishing.
"""
import concurrent.futures
from datetime import datetime, timezone

try:
    import whois as pywhois
    from whois.parser import PywhoisError
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    from dateutil import parser as dateutil_parser
    DATEUTIL_AVAILABLE = True
except ImportError:
    DATEUTIL_AVAILABLE = False

# python-whois sets a 10s timeout PER socket hop internally, and a single
# lookup can involve 2-3 hops (root registry -> registrar referral ->
# sometimes a second referral) -- so a single call can legitimately take
# 20-30s with no way to configure that from the outside. Domain age is a
# nice-to-have risk signal, not something worth blocking the whole analysis
# pipeline on, so it's capped here at a hard wall-clock timeout: if WHOIS
# hasn't answered by then, treat it as unavailable and move on.
WHOIS_TIMEOUT_SECONDS = 6
_whois_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix='whois')

# python-whois raises PywhoisError with the raw registry response text as
# the message for a wide range of situations (unparseable response, TLD
# quirks, and -- most commonly -- the domain simply isn't registered). The
# raw text is often mostly registry legal boilerplate, which reads as
# unpolished/broken if shown verbatim. These patterns identify the common
# "not registered" case so it can be reported cleanly instead.
_NO_MATCH_PATTERNS = (
    'no match', 'not found', 'no data found', 'no entries found',
    'domain not found', 'status: free', 'no object found', 'nothing found',
)



def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _coerce_to_datetime(value):
    """python-whois returns creation_date as a parsed datetime for most
    TLDs, but for some registrars/TLDs it comes back as a raw string
    instead (format varies by registry). Without this fallback,
    domain-age/newly-registered detection silently never fires for those
    domains -- no error, it just skips the check."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and DATEUTIL_AVAILABLE:
        try:
            return dateutil_parser.parse(value)
        except (ValueError, OverflowError):
            return None
    return None


def _run_whois_query(domain):
    """The actual blocking call, run in a worker thread so it can be
    abandoned (from the caller's perspective) if it overruns the timeout --
    the underlying socket call itself has no external cancel hook."""
    w = pywhois.whois(domain)
    creation_date = _coerce_to_datetime(_first(w.creation_date))
    expiration_date = _first(w.expiration_date)

    domain_age_days = None
    is_newly_registered = False
    if creation_date is not None:
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


def lookup_domain(domain):
    if not domain:
        return {'status': 'no_domain'}
    if not WHOIS_AVAILABLE:
        return {'status': 'unavailable', 'message': 'python-whois not installed', 'domain': domain}

    future = _whois_executor.submit(_run_whois_query, domain)
    try:

        return future.result(timeout=WHOIS_TIMEOUT_SECONDS)
    except concurrent.futures.TimeoutError:
        # The query thread is left to finish/die on its own in the background
        # (Python has no clean way to kill a thread mid-socket-call) -- but
        # the analysis pipeline is no longer waiting on it.
        return {'status': 'timeout', 'message': f'WHOIS lookup exceeded {WHOIS_TIMEOUT_SECONDS}s', 'domain': domain}
    except PywhoisError as e:
        text = str(e)
        if any(p in text.lower() for p in _NO_MATCH_PATTERNS):
            return {
                'status': 'not_registered',
                'message': 'No WHOIS record found for this domain -- it does not appear to be '
                           'registered, which is itself unusual for a domain actively sending mail.',
                'domain': domain,
            }
        return {'status': 'failed', 'message': text[:200] + ('...' if len(text) > 200 else ''), 'domain': domain}
    except Exception as e:
        return {'status': 'failed', 'message': str(e)[:200], 'domain': domain}