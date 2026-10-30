"""
URL / website reputation signals for the "Is this really their website?"
check. Each signal is independent, optional and fails soft; the caller gets
a list of plain-language signals plus a 'dangerous' verdict only when a
real blacklist says so.

  - Google Safe Browsing (GOOGLE_SAFE_BROWSING_API_KEY): Google's own
    phishing / malware / unwanted-software lists -- the most trustworthy
    "this link is known-bad" source available for free.
  - VirusTotal (VIRUSTOTAL_API_KEY): how many security engines flag the URL.
  - Wikidata (no key): a brand's *official website* as recorded in a public,
    structured knowledge base -- a far safer source than "whatever ranks
    first in a web search" (see wikidata_official_domains).
  - Domain age (WHOIS; no key): scam sites are usually days or weeks old.
  - Local lexical red flags (no key): punycode / look-alike characters, '@'
    tricks, raw IP hosts, shorteners, plain http, free/abused TLDs, deep
    subdomain stacks.
"""
import base64
import concurrent.futures
import difflib
import ipaddress
import re
import os
from urllib.parse import urlparse

import requests

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls/{id}"
WIKIDATA_API = "https://www.wikidata.org/w/api.php"
DEFAULT_TIMEOUT = 5
USER_AGENT = "FORENSIQ-site-check/1.0 (phishing analysis tool)"

SUSPICIOUS_TLDS = {
    'zip', 'mov', 'top', 'xyz', 'click', 'country', 'gq', 'tk', 'ml', 'ga', 'cf',
    'work', 'rest', 'fit', 'icu', 'cyou', 'cfd', 'sbs', 'support', 'monster', 'buzz',
}
SHORTENERS = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
              'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bl.ink', 'lnkd.in', 'v.gd'}


def _signal(name, level, text):
    return {'name': name, 'level': level, 'text': text}   # level: bad / warn / ok / info


# ---------------------------------------------------------------- blacklists
def google_safe_browsing(url, timeout=DEFAULT_TIMEOUT):
    key = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY')
    if not key:
        return {'status': 'not_configured'}
    try:
        resp = requests.post(
            SAFE_BROWSING_URL, params={'key': key}, timeout=timeout,
            json={
                'client': {'clientId': 'forensiq', 'clientVersion': '1.0'},
                'threatInfo': {
                    'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}],
                },
            },
        )
        resp.raise_for_status()
        matches = resp.json().get('matches') or []
        return {'status': 'success', 'threats': sorted({m.get('threatType', 'UNKNOWN') for m in matches})}
    except requests.exceptions.RequestException as e:
        return {'status': 'unavailable', 'message': str(e)[:200]}
    except ValueError as e:
        return {'status': 'unavailable', 'message': f'Unexpected response: {e}'}


def virustotal(url, timeout=DEFAULT_TIMEOUT):
    key = os.environ.get('VIRUSTOTAL_API_KEY')
    if not key:
        return {'status': 'not_configured'}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    try:
        resp = requests.get(VIRUSTOTAL_URL.format(id=url_id), headers={'x-apikey': key}, timeout=timeout)
        if resp.status_code == 404:
            return {'status': 'success', 'known': False}
        resp.raise_for_status()
        stats = resp.json()['data']['attributes']['last_analysis_stats']
        return {'status': 'success', 'known': True,
                'malicious': int(stats.get('malicious', 0)), 'suspicious': int(stats.get('suspicious', 0)),
                'harmless': int(stats.get('harmless', 0))}
    except requests.exceptions.RequestException as e:
        return {'status': 'unavailable', 'message': str(e)[:200]}
    except (ValueError, KeyError, TypeError) as e:
        return {'status': 'unavailable', 'message': f'Unexpected response: {e}'}


# ------------------------------------------------------------------ wikidata
def _norm(text):
    return re.sub(r'[^a-z0-9]', '', (text or '').lower())


def wikidata_official_domains(brand_name, timeout=DEFAULT_TIMEOUT):
    """Official website(s) of the organisation named `brand_name`, from
    Wikidata property P856. Only the single best entity is used, and only
    if its name (or an alias) matches the brand closely -- if the match is
    shaky we return nothing rather than guess."""
    from modules.url_scan import _registrable_domain
    try:
        headers = {'User-Agent': USER_AGENT}
        found = requests.get(WIKIDATA_API, headers=headers, timeout=timeout, params={
            'action': 'wbsearchentities', 'search': brand_name, 'language': 'en',
            'type': 'item', 'limit': 5, 'format': 'json'})
        found.raise_for_status()
        wanted = _norm(brand_name)
        chosen = None
        for item in found.json().get('search', []):
            labels = [item.get('label')] + [item.get('match', {}).get('text')]
            if any(difflib.SequenceMatcher(None, _norm(l), wanted).ratio() >= 0.88 for l in labels if l):
                chosen = item
                break
        if not chosen:
            return {'status': 'success', 'domains': [], 'entity': None}
        ent = requests.get(WIKIDATA_API, headers=headers, timeout=timeout, params={
            'action': 'wbgetentities', 'ids': chosen['id'], 'props': 'claims', 'format': 'json'})
        ent.raise_for_status()
        claims = ent.json()['entities'][chosen['id']].get('claims', {}).get('P856', [])
        domains = []
        for c in claims:
            if c.get('rank') == 'deprecated':
                continue
            url = (((c.get('mainsnak') or {}).get('datavalue') or {}).get('value')) or ''
            host = (urlparse(url).hostname or '').lower()
            d = _registrable_domain(host)
            if d and d not in domains:
                domains.append(d)
        return {'status': 'success', 'domains': domains, 'entity': chosen.get('label')}
    except requests.exceptions.RequestException as e:
        return {'status': 'unavailable', 'message': str(e)[:200]}
    except (ValueError, KeyError, TypeError) as e:
        return {'status': 'unavailable', 'message': f'Unexpected response: {e}'}


# --------------------------------------------------------- lexical red flags
def lexical_signals(url, host):
    out = []
    parsed = urlparse(url if '://' in url else 'https://' + url)
    netloc = parsed.netloc
    labels = host.split('.')
    tld = labels[-1] if labels else ''

    try:
        ipaddress.ip_address(host)
        out.append(_signal('ip_host', 'bad', 'The link points to a raw IP address instead of a name -- real brands almost never do this.'))
    except ValueError:
        pass
    if '@' in netloc:
        out.append(_signal('at_sign', 'bad', "The link contains '@' -- everything before it is ignored by the browser, a classic trick to disguise the real destination."))
    if any(l.startswith('xn--') for l in labels):
        out.append(_signal('punycode', 'bad', 'The address uses look-alike (international) characters that can imitate a real brand name.'))
    elif any(ord(ch) > 127 for ch in host):
        out.append(_signal('non_ascii', 'bad', 'The address contains non-English characters that can imitate a real brand name.'))
    if host in SHORTENERS:
        out.append(_signal('shortener', 'warn', 'This is a shortened link -- the real destination is hidden.'))
    if parsed.scheme == 'http':
        out.append(_signal('no_https', 'warn', 'The link is not encrypted (http, not https).'))
    if tld in SUSPICIOUS_TLDS:
        out.append(_signal('tld', 'warn', f'".{tld}" is a cheap/free ending that is heavily used by scam sites.'))
    if len(labels) >= 5:
        out.append(_signal('deep_subdomain', 'warn', 'The address has an unusually long chain of sub-names, often used to bury a fake brand name.'))
    if len(host) > 45:
        out.append(_signal('long_host', 'warn', 'The address is unusually long.'))
    return out


# ----------------------------------------------------------------- domain age
def domain_age_signal(domain):
    try:
        from modules import whois_lookup
        w = whois_lookup.lookup_domain(domain)
    except Exception:
        return None
    if w.get('status') != 'success':
        return None
    days = w.get('domain_age_days')
    if days is None:
        return None
    if days < 30:
        return _signal('domain_age', 'bad', f'This domain was registered only {days} day(s) ago -- scam sites are usually brand new.')
    if days < 180:
        return _signal('domain_age', 'warn', f'This domain is only {days} days old (about {days // 30} months).')
    return _signal('domain_age', 'ok', f'This domain has existed for {days // 365} year(s), {days % 365 // 30} month(s).')


# ----------------------------------------------------------------- aggregator
def gather_signals(url, host, domain, skip_age=False):
    """Run the checks concurrently (wall-clock bounded by the slowest,
    ~5s) and return {'signals': [...], 'dangerous': bool, 'threats': [...],
    'sources': {name: status}}."""
    signals = lexical_signals(url, host)
    sources = {}
    dangerous, threats = False, []

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        f_sb = pool.submit(google_safe_browsing, url)
        f_vt = pool.submit(virustotal, url)
        f_age = None if skip_age else pool.submit(domain_age_signal, domain)

        def result(fut, default):
            try:
                return fut.result(timeout=DEFAULT_TIMEOUT + 1)
            except Exception:
                return default

        sb = result(f_sb, {'status': 'unavailable'})
        vt = result(f_vt, {'status': 'unavailable'})
        age = result(f_age, None) if f_age else None

    sources['google_safe_browsing'] = sb.get('status')
    if sb.get('status') == 'success':
        if sb['threats']:
            dangerous = True
            threats += sb['threats']
            pretty = ', '.join(t.replace('_', ' ').lower() for t in sb['threats'])
            signals.insert(0, _signal('safe_browsing', 'bad', f'Google Safe Browsing lists this link as dangerous ({pretty}).'))
        else:
            signals.append(_signal('safe_browsing', 'ok', 'Not on Google Safe Browsing\'s danger lists (this does not mean it is safe -- new scam sites take time to be listed).'))

    sources['virustotal'] = vt.get('status')
    if vt.get('status') == 'success' and vt.get('known'):
        bad = vt['malicious'] + vt['suspicious']
        if vt['malicious'] >= 3:
            dangerous = True
            threats.append('VIRUSTOTAL_MALICIOUS')
            signals.insert(0, _signal('virustotal', 'bad', f"{vt['malicious']} security engines on VirusTotal flag this link as malicious."))
        elif bad >= 1:
            signals.append(_signal('virustotal', 'warn', f'{bad} security engine(s) on VirusTotal flag this link.'))
        else:
            signals.append(_signal('virustotal', 'ok', 'No security engine on VirusTotal flags this link.'))

    if age:
        signals.append(age)
    return {'signals': signals, 'dangerous': dangerous, 'threats': threats, 'sources': sources}
