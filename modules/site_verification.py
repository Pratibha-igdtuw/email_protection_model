"""
Module: Claimed-brand vs. official-website verification ("elderly mode").

Given a brand/bank name and a link someone was sent claiming to be that
brand, looks up the brand's actual official website via TinyFish Search
and compares registrable domains. Produces one plain-language verdict
line, suitable for a non-technical user, plus the evidence behind it.
"""
import os
import requests
from urllib.parse import urlparse

from modules.url_scan import _registrable_domain

SEARCH_URL = "https://api.search.tinyfish.ai"

DEFAULT_TIMEOUT = 6


def verify_official_site(brand_name, claimed_url, timeout=DEFAULT_TIMEOUT):
    """Check whether claimed_url's domain matches brand_name's official site.

    Args:
        brand_name: the brand/bank the link claims to belong to, e.g. "SBI".
        claimed_url: the URL the user was actually sent.
        timeout: request timeout in seconds.

    Returns:
        dict with 'status' of 'not_configured' / 'no_input' /
        'unavailable' / 'success'. On 'success', also includes
        'claimed_domain', 'official_domains', 'is_official', and a
        plain-language 'verdict' string.
    """
    api_key = os.environ.get('TINYFISH_API_KEY')
    if not api_key:
        return {'status': 'not_configured'}
    if not brand_name or not claimed_url:
        return {'status': 'no_input'}

    claimed_host = (urlparse(claimed_url).hostname or claimed_url).lower()
    claimed_domain = _registrable_domain(claimed_host)

    try:
        resp = requests.get(
            SEARCH_URL,
            headers={'X-API-Key': api_key},
            params={'query': f"{brand_name} official website", 'location': 'IN'},
            timeout=timeout,
        )
        resp.raise_for_status()
        results = resp.json().get('results', [])[:3]

        official_domains = []
        for r in results:
            host = (urlparse(r.get('url', '')).hostname or '').lower()
            domain = _registrable_domain(host)
            if domain and domain not in official_domains:
                official_domains.append(domain)

        is_official = claimed_domain in official_domains

        if is_official:
            verdict = f"This looks like the official website for {brand_name}."
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

        return {
            'status': 'success',
            'claimed_domain': claimed_domain,
            'official_domains': official_domains,
            'is_official': is_official,
            'verdict': verdict,
        }

    except requests.exceptions.RequestException as e:
        return {'status': 'unavailable', 'message': str(e)}
    except (ValueError, KeyError) as e:
        return {'status': 'unavailable', 'message': f'Unexpected response: {e}'}