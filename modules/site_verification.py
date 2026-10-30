"""
Module: Claimed-brand vs. official-website verification ("elderly mode").

Given a brand/bank name and a link someone was sent claiming to be that
brand, decides whether the link really belongs to that brand and produces
one plain-language verdict line plus the evidence behind it.

Where the "official" domains come from (in priority order):
  1. A small curated table of the most-impersonated brands (KNOWN_OFFICIAL).
     This works with no API key and cannot be fooled by search noise.
  2. Live web search (TinyFish) for "<brand> official website" -- but only
     results that look like the brand's own site are accepted. Search
     results are NOT trusted blindly: an earlier version treated the top 3
     results as official, so unrelated big sites (google.com showed up for
     "whatsapp") became "official" and any link to them passed.

Other things this module guards against:
  - Copycat domains: a link whose domain is a near-miss of an official one
    (whatsap.com, paypa1.com) is called out as a copycat, not just "not
    official".
  - Shared hosting / user-content domains (github.io, blogspot.com,
    web.app, ...): anyone can create a sub-address there, so a subdomain
    of one is never treated as the brand's own.
  - Made-up sub-addresses (delt.whatsapp.com): a name under the official
    domain proves the domain is theirs, not that this particular address
    exists. A sub-address is only called official when DNS positively
    confirms it exists (and the domain does not answer for every made-up
    name, i.e. no wildcard DNS). If it doesn't exist, or can't be
    confirmed, it is NOT passed as official.
"""
import difflib
import os
import re
import requests
from urllib.parse import urlparse

from modules import url_reputation
from modules.url_scan import _registrable_domain

SEARCH_URL = "https://api.search.tinyfish.ai"

DEFAULT_TIMEOUT = 6

# Brand alias (lower-case words) -> official registrable domains. Only
# domains the brands themselves are well known to operate.
KNOWN_OFFICIAL = {
    'whatsapp': ['whatsapp.com', 'whatsapp.net', 'wa.me'],
    'sbi': ['sbi.co.in', 'onlinesbi.sbi', 'sbicard.com', 'sbilife.co.in'],
    'state bank of india': ['sbi.co.in', 'onlinesbi.sbi'],
    'hdfc': ['hdfcbank.com', 'hdfc.com', 'hdfclife.com'],
    'hdfc bank': ['hdfcbank.com'],
    'icici': ['icicibank.com', 'icicilombard.com', 'iciciprulife.com'],
    'icici bank': ['icicibank.com'],
    'axis bank': ['axisbank.com'],
    'kotak': ['kotak.com', 'kotakbank.com'],
    'punjab national bank': ['pnbindia.in'],
    'pnb': ['pnbindia.in'],
    'paytm': ['paytm.com'],
    'phonepe': ['phonepe.com'],
    'google pay': ['pay.google.com', 'google.com'],
    'amazon': ['amazon.in', 'amazon.com'],
    'flipkart': ['flipkart.com'],
    'paypal': ['paypal.com'],
    'google': ['google.com', 'google.co.in'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com'],
    'apple': ['apple.com', 'icloud.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'instagram': ['instagram.com'],
    'netflix': ['netflix.com'],
    'income tax': ['incometax.gov.in', 'incometaxindia.gov.in'],
    'income tax dept': ['incometax.gov.in'],
    'income tax department': ['incometax.gov.in'],
    'aadhaar': ['uidai.gov.in'],
    'uidai': ['uidai.gov.in'],
    'irctc': ['irctc.co.in'],
    'epfo': ['epfindia.gov.in'],
}

# Sites that appear in almost any search result list. They are never "the
# brand's official site" unless the brand itself is one of them.
AGGREGATOR_DOMAINS = {
    'google.com', 'google.co.in', 'bing.com', 'yahoo.com', 'duckduckgo.com',
    'wikipedia.org', 'facebook.com', 'youtube.com', 'linkedin.com', 'twitter.com',
    'x.com', 'instagram.com', 'reddit.com', 'quora.com', 'pinterest.com',
    'play.google.com', 'apps.apple.com', 'medium.com', 'trustpilot.com',
}

# Anyone can publish a page under these, so "sub.<this>" proves nothing.
SHARED_HOSTING_DOMAINS = {
    'github.io', 'blogspot.com', 'web.app', 'firebaseapp.com', 'herokuapp.com',
    'netlify.app', 'vercel.app', 'pages.dev', 'weebly.com', 'wixsite.com',
    'wordpress.com', 'sites.google.com', 'azurewebsites.net', 'onrender.com',
    'ngrok.io', 'glitch.me', 'repl.co', 'duckdns.org', 'tk', 'ml', 'ga', 'cf', 'gq',
}

COPYCAT_SIMILARITY = 0.8

# Words scammers bolt onto a brand name. A search hit like
# "whatsapp-login-help.com" contains the brand but is never the brand's own site.
LOOKALIKE_WORDS = (
    'login', 'signin', 'secure', 'verify', 'verification', 'support', 'help', 'update',
    'account', 'care', 'customer', 'service', 'official', 'online', 'alert', 'refund',
    'reward', 'offer', 'free', 'claim', 'kyc', 'portal', 'billing', 'payment', 'recover',
)


def _tokens(text):
    return re.findall(r'[a-z0-9]+', (text or '').lower())


def _known_domains_for(brand_name):
    """Curated official domains for this brand, matched on whole words
    (so 'apple' does not match 'pineapple'). Longest alias wins."""
    padded = ' ' + ' '.join(_tokens(brand_name)) + ' '
    best_alias = None
    for alias in KNOWN_OFFICIAL:
        if f' {alias} ' in padded and (best_alias is None or len(alias) > len(best_alias)):
            best_alias = alias
    return list(KNOWN_OFFICIAL[best_alias]) if best_alias else []


def _domain_label(domain):
    parts = (domain or '').split('.')
    return parts[0] if parts else ''


def _looks_like_brand(domain, brand_name):
    """Is this domain plausibly the brand's own site (brand name appears in
    its main label, or the other way round)?"""
    label = re.sub(r'[^a-z0-9]', '', _domain_label(domain))
    brand_joined = ''.join(_tokens(brand_name))
    if not label or not brand_joined:
        return False
    if len(label) >= 3 and (label in brand_joined or brand_joined in label):
        return True
    return any(len(t) >= 3 and (t in label or label in t) for t in _tokens(brand_name))


def _filter_search_domains(domains, brand_name):
    """Keep only search-result domains that can credibly be the brand's own."""
    brand_joined = ''.join(_tokens(brand_name))
    kept = []
    for d in domains:
        if d in AGGREGATOR_DOMAINS and _domain_label(d) not in brand_joined:
            continue
        label = _domain_label(d)
        if any(w in label for w in LOOKALIKE_WORDS) and label != brand_joined:
            continue
        if _looks_like_brand(d, brand_name) or d.endswith('.gov.in') or d.endswith('.gov'):
            kept.append(d)
    return kept


def _host_exists(host, timeout=2):
    """False ONLY when DNS positively says the name does not exist.
    Timeouts, no network, or any other trouble return None (unknown) so a
    flaky resolver never turns a good link into a scary one."""
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        return None
    try:
        dns.resolver.resolve(host, 'A', lifetime=timeout)
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return True  # the name exists, it just has no A record
    except (dns.exception.DNSException, Exception):
        return None


def _has_wildcard_dns(domain):
    """True if the domain answers for any made-up sub-name (wildcard DNS) --
    in which case 'this sub-address resolves' proves nothing."""
    import uuid
    return _host_exists(f"zz-{uuid.uuid4().hex[:12]}.{domain}") is True


def _copycat_of(claimed_domain, official_domains):
    for off in official_domains:
        if claimed_domain != off and difflib.SequenceMatcher(None, claimed_domain, off).ratio() >= COPYCAT_SIMILARITY:
            return off
    return None


def verify_official_site(brand_name, claimed_url, timeout=DEFAULT_TIMEOUT):
    """Check whether claimed_url really belongs to brand_name.

    Returns a dict with 'status' of 'not_configured' / 'no_input' /
    'unavailable' / 'success'. On 'success' it also has 'claimed_host' (the
    full address that was entered), 'claimed_domain', 'official_domains',
    'is_official', 'note' (optional extra caution) and a plain-language
    'verdict'.
    """
    if not brand_name or not claimed_url:
        return {'status': 'no_input'}

    api_key = os.environ.get('TINYFISH_API_KEY')
    known = _known_domains_for(brand_name)

    raw = claimed_url.strip()
    parse_target = raw if '://' in raw else 'https://' + raw
    claimed_host = (urlparse(parse_target).hostname or raw).lower().rstrip('.')
    claimed_domain = _registrable_domain(claimed_host)
    is_subdomain = claimed_host not in (claimed_domain, 'www.' + claimed_domain)

    official_domains = list(known)
    search_error = None
    official_source = 'curated list' if known else None
    if not known:
        # Wikidata first: a public, structured record of the brand's official site.
        wd = url_reputation.wikidata_official_domains(brand_name)
        if wd.get('status') == 'success' and wd.get('domains'):
            official_domains = list(wd['domains'])
            official_source = f"Wikidata ({wd.get('entity')})"
    if not official_domains and api_key:
        try:
            resp = requests.get(
                SEARCH_URL,
                headers={'X-API-Key': api_key},
                params={'query': f"{brand_name} official website", 'location': 'IN'},
                timeout=timeout,
            )
            resp.raise_for_status()
            found = []
            for r in resp.json().get('results', [])[:5]:
                host = (urlparse(r.get('url', '')).hostname or '').lower()
                domain = _registrable_domain(host)
                if domain and domain not in found:
                    found.append(domain)
            official_domains = _filter_search_domains(found, brand_name)
            if official_domains:
                official_source = 'web search (weaker evidence)'
        except requests.exceptions.RequestException as e:
            search_error = str(e)
        except (ValueError, KeyError) as e:
            search_error = f'Unexpected response: {e}'

    if search_error and not official_domains:
        return {'status': 'unavailable', 'message': search_error}

    shared_host = claimed_domain in SHARED_HOSTING_DOMAINS or claimed_host.split('.')[-1] in SHARED_HOSTING_DOMAINS
    is_official = (claimed_domain in official_domains) and not shared_host
    note = None
    resolves = None

    if is_official and is_subdomain:
        sub = claimed_host[:-len(claimed_domain) - 1]
        resolves = _host_exists(claimed_host)
        if resolves is False:
            is_official = False
            verdict = (
                f"Do NOT trust this link. The domain {claimed_domain} belongs to {brand_name}, "
                f"but the address \"{claimed_host}\" does not exist -- anyone can type a made-up "
                f"name in front of a real domain. Likely a typing mistake or a trick."
            )
        elif resolves is None or _has_wildcard_dns(claimed_domain):
            is_official = False
            verdict = (
                f"Could NOT confirm this link. {claimed_domain} is {brand_name}'s domain, but we "
                f"could not verify that \"{sub}\" is a real {brand_name} address. "
                f"Don't open it unless you are certain; use the official app or {claimed_domain} directly."
            )
        else:
            verdict = f"This looks like an official address of {brand_name} ({claimed_domain})."
            note = (f"\"{sub}\" is a sub-address of {claimed_domain} and it exists. "
                    "Only open it if you expected this exact link.")
    elif is_official:
        verdict = f"This looks like the official website for {brand_name}."
    else:
        copycat = _copycat_of(claimed_domain, official_domains)
        if shared_host:
            verdict = (
                f"This is NOT {brand_name}'s official website. {claimed_domain} is a free hosting/domain "
                "service where anyone can create a page, so it can't be the brand's own site."
            )
        elif copycat:
            verdict = (
                f"WARNING: this looks like a COPYCAT of {copycat}. It is not {brand_name}'s "
                f"official website. The real one is {copycat}."
            )
        elif official_domains:
            verdict = (
                f"This is NOT {brand_name}'s official website. "
                f"The official site appears to be: {official_domains[0]}"
            )
        else:
            verdict = (
                f"Could not confirm {brand_name}'s official website -- "
                "do not trust this link. Verify directly through the brand's official app or a branch you trust."
            )

    # Independent reputation signals (Safe Browsing, VirusTotal, domain age,
    # look-alike/lexical red flags). A real blacklist hit overrides everything,
    # including "is on the official domain" -- official domains can host
    # compromised or abused pages.
    rep = url_reputation.gather_signals(parse_target, claimed_host, claimed_domain,
                                        skip_age=(is_official and not is_subdomain))
    signals = rep['signals']
    threat = rep['dangerous']
    if threat:
        is_official = False
        verdict = (f"DANGEROUS LINK -- do not open it. It is flagged by a security blacklist"
                   f" ({', '.join(t.replace('_', ' ').lower() for t in rep['threats'])}). "
                   f"{verdict}")
    elif not is_official and any(sig['level'] == 'bad' for sig in signals) and not verdict.startswith(('WARNING', 'Do NOT')):
        verdict = verdict + " Several warning signs below also point to a fake link."

    return {
        'status': 'success',
        'claimed_host': claimed_host,
        'claimed_domain': claimed_domain,
        'official_domains': official_domains,
        'official_source': official_source,
        'is_official': is_official,
        'threat': threat,
        'host_resolves': resolves,
        'note': note,
        'signals': signals,
        'signal_sources': rep['sources'],
        'verdict': verdict,
    }
