"""
Module: URL risk analysis
Flags suspicious characteristics in URLs found in an email: a raw IP
address instead of a domain, known URL-shortener services (hide the real
destination), punycode/IDN domains (can disguise homoglyph lookalike
characters), a well-known brand name stuffed into a subdomain or path
while the actual registrable domain is unrelated, and -- where the HTML
body is available -- a mismatch between a link's visible text and its
real href target (classic "click here: https://your-bank.com" trick where
the href goes somewhere else entirely).

Heuristic red-flagging, consistent with the rest of this pipeline -- not a
live URL-scanning/Safe-Browsing-style service. It does not follow
redirects or inspect the destination page.
"""
import re
from urllib.parse import urlparse

KNOWN_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bl.ink',
    'lnkd.in', 'tr.im', 'v.gd', 'shorte.st',
}

# A small, illustrative set of frequently-impersonated brand/institution
# names -- used only to catch the "brand name stuffed into a subdomain or
# path while the real domain is unrelated" pattern. Not exhaustive.
WATCHED_BRANDS = {
    'paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix',
    'facebook', 'instagram', 'whatsapp', 'bankofamerica', 'chase',
    'wellsfargo', 'hdfcbank', 'icicibank', 'sbi', 'irctc', 'github',
    'linkedin', 'outlook', 'office365', 'gmail',
}

IPV4_HOST_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

_ANCHOR_REGEX = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
_TAG_STRIP_REGEX = re.compile(r'<[^>]+>')


def _defang(url):
    """Renders a URL in the standard SOC/threat-intel 'defanged' form
    (http -> hxxp, :// -> [://], . -> [.]) so it can be displayed to an
    analyst without being clickable or auto-linkified by the browser --
    the whole point of showing a suspected-phishing URL in a report is
    to look at it, not to visit it. Purely cosmetic: only used for
    display, never for any of the actual host/IP/shortener detection
    logic below, which all runs on the real URL."""
    return url.replace('http', 'hxxp', 1).replace('://', '[://]', 1).replace('.', '[.]')


def _registrable_domain(hostname):
    """Rough registrable-domain approximation: last two labels, or three
    for common ccTLD-second-level patterns like .co.in / .co.uk. Good
    enough for 'does this brand appear as the ACTUAL domain vs. just a
    subdomain label' -- not a full public-suffix-list implementation."""
    if not hostname:
        return hostname
    labels = hostname.lower().split('.')
    if len(labels) >= 3 and labels[-2] in ('co', 'com', 'org', 'gov', 'ac', 'net') and len(labels[-1]) == 2:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:]) if len(labels) >= 2 else hostname


def _find_anchor_mismatches(body_html):
    """<a> tags where the visible text itself looks like a URL/domain but
    the real href points somewhere else -- a very common phishing trick."""
    if not body_html:
        return []
    mismatches = []
    for href, inner in _ANCHOR_REGEX.findall(body_html):
        visible_text = _TAG_STRIP_REGEX.sub('', inner).strip()
        text_host_match = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', visible_text)
        if not text_host_match:
            continue
        text_host = text_host_match.group(1).lower()
        try:
            href_host = (urlparse(href).hostname or '').lower()
        except ValueError:
            continue
        if href_host and text_host and href_host != text_host and not href_host.endswith('.' + text_host):
            mismatches.append({
                'text': visible_text[:80],
                'href': href[:200],
                'href_defanged': _defang(href[:200]),
            })
    return mismatches


def analyze_urls(urls, body_html=None):
    """
    urls: list of URL strings (as already extracted by parser.extract_urls).
    body_html: optional raw HTML body, used only for anchor-text/href
    mismatch detection when available.

    Returns {'urls': [...per-url details...], 'count': int,
             'anchor_mismatches': [...], 'risk_score': int (0-15),
             'flags': [human-readable strings]}.
    risk_score is the WORST single finding, not a sum -- an email with
    many ordinary links shouldn't outscore one with a single IP-literal
    phishing link just because it has more URLs in it.
    """
    results = []
    flags = []
    worst_score = 0

    for url in (urls or []):
        try:
            parsed = urlparse(url)
        except ValueError:
            continue
        host = (parsed.hostname or '').lower()
        url_flags = []
        url_score = 0

        is_ip_literal = bool(IPV4_HOST_REGEX.match(host)) or (':' in host and '.' not in host)
        if is_ip_literal:
            url_flags.append("Uses a raw IP address instead of a domain name")
            url_score += 12

        is_shortener = host in KNOWN_SHORTENERS
        if is_shortener:
            url_flags.append(f"Known URL-shortener ({host}) -- real destination is hidden")
            url_score += 8

        is_punycode = 'xn--' in host
        if is_punycode:
            url_flags.append("Punycode/IDN domain -- may visually disguise lookalike characters")
            url_score += 10

        registrable = _registrable_domain(host)
        brand_impersonation = None
        path_lower = (parsed.path or '').lower()
        if not is_ip_literal:
            for brand in WATCHED_BRANDS:
                if brand in host and brand not in registrable:
                    brand_impersonation = brand
                    break
            if not brand_impersonation:
                for brand in WATCHED_BRANDS:
                    if brand in path_lower and brand not in registrable:
                        brand_impersonation = brand
                        break
        if brand_impersonation:
            url_flags.append(
                f"Mentions \"{brand_impersonation}\" but the actual domain is "
                f"\"{registrable}\" -- possible impersonation")
            url_score += 12

        results.append({
            'url': url,
            'defanged_url': _defang(url),
            'host': host,
            'is_ip_literal': is_ip_literal,
            'is_shortener': is_shortener,
            'is_punycode': is_punycode,
            'brand_impersonation': brand_impersonation,
            'risk_flags': url_flags,
        })
        flags.extend(f"{url}: {f}" for f in url_flags)
        worst_score = max(worst_score, url_score)

    anchor_mismatches = _find_anchor_mismatches(body_html)
    for mismatch in anchor_mismatches:
        flags.append(f"Link text says \"{mismatch['text']}\" but actually points to \"{mismatch['href']}\"")
        worst_score = max(worst_score, 14)

    return {
        'urls': results,
        'count': len(results),
        'anchor_mismatches': anchor_mismatches,
        'risk_score': min(worst_score, 15),
        'flags': flags,
    }