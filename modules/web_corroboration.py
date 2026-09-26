"""
Module: Live web corroboration via TinyFish Search + Fetch.

Cross-checks a domain or phone number against the LIVE web -- not just
the bundled PhishTank snapshot -- so an analyst also sees real-time scam
reports, with citation links back to the source.

Fails gracefully with the same status vocabulary used across the other
external-lookup modules in this project (see blacklist.check_abuseipdb):
  - 'not_configured' -- TINYFISH_API_KEY is not set
  - 'no_indicator'   -- nothing to check (e.g. sender_domain was empty)
  - 'unavailable'    -- the TinyFish API call itself failed/timed out
  - 'success'        -- call succeeded (citations may still be empty)

Design note: this result is deliberately NOT fed into
risk_score.compute_combined_score(). It is corroborating evidence for a
human analyst, not a score input -- a noisy or unrelated search result
should never be able to swing the numeric verdict.
"""
import os
import requests

SEARCH_URL = "https://api.search.tinyfish.ai"
FETCH_URL = "https://api.fetch.tinyfish.ai"

DEFAULT_TIMEOUT = 6


def check_web_corroboration(indicator, timeout=DEFAULT_TIMEOUT):
    """Look up live web scam reports for a domain or phone number.

    Args:
        indicator: a domain (e.g. 'example.com') or phone number string.
        timeout: per-request timeout in seconds for both the Search and
            the Fetch calls.

    Returns:
        dict with keys:
            status: one of 'not_configured' / 'no_indicator' /
                'unavailable' / 'success'
            query: the search query used (only on 'success')
            citations: list of {'title', 'url', 'snippet'} (only on
                'success'; may be an empty list if nothing was found)
            message: human-readable detail (only on failure statuses)
    """
    api_key = os.environ.get('TINYFISH_API_KEY')
    if not api_key:
        return {
            'status': 'not_configured',
            'message': 'Set TINYFISH_API_KEY to enable live web corroboration.',
        }
    if not indicator:
        return {'status': 'no_indicator', 'citations': []}

    query = f"{indicator} scam reports"
    try:
        search_resp = requests.get(
            SEARCH_URL,
            headers={'X-API-Key': api_key},
            params={'query': query, 'location': 'IN'},
            timeout=timeout,
        )
        search_resp.raise_for_status()
        results = search_resp.json().get('results', [])[:3]
        if not results:
            return {'status': 'success', 'query': query, 'citations': []}

        urls = [r['url'] for r in results if r.get('url')]
        citations = []
        fetched_text_by_url = {}
        if urls:
            fetch_resp = requests.post(
                FETCH_URL,
                headers={'X-API-Key': api_key, 'Content-Type': 'application/json'},
                json={'urls': urls, 'format': 'markdown'},
                timeout=timeout,
            )
            fetch_resp.raise_for_status()
            for item in fetch_resp.json().get('results', []):
                fetched_text_by_url[item.get('url')] = item.get('text', '')

        for r in results:
            text = fetched_text_by_url.get(r.get('url')) or r.get('snippet', '')
            citations.append({
                'title': r.get('title'),
                'url': r.get('url'),
                'snippet': (text or '').strip()[:220],
            })

        return {'status': 'success', 'query': query, 'citations': citations}

    except requests.exceptions.RequestException as e:
        return {'status': 'unavailable', 'message': str(e)}
    except (ValueError, KeyError) as e:
        # Malformed/unexpected JSON from the API -- treat like any other
        # unavailable upstream rather than raising into the pipeline.
        return {'status': 'unavailable', 'message': f'Unexpected response: {e}'}
