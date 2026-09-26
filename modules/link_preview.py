"""
Module: Safe, sandboxed link preview via the TinyFish Agent.

Visits a suspicious URL inside TinyFish's own sandboxed browser --
never the investigator's (or an elderly user's) real IP or browser --
and reports back in plain language what the page does, whether it asks
for a password/OTP, and where it actually ends up after redirects.

This calls TinyFish's metered Agent API (unlike Search/Fetch, which are
free), so it is meant to be invoked on demand -- one click, one link --
not automatically for every URL in every analyzed email. Rate-limit the
Flask route that calls this (see app.py: /preview-link).
"""
import os
import requests

AGENT_URL = "https://agent.tinyfish.ai/v1/automation/run"

DEFAULT_TIMEOUT = 45

GOAL = (
    "Visit this page. In plain, simple language, describe what it shows "
    "in 2-3 sentences. State clearly whether it contains a login form, "
    "or asks the visitor for a password or a one-time code (OTP). "
    "Report the final URL after following any redirects. Return JSON "
    "with keys: description, has_login_form, requests_otp, final_url."
)


def safe_preview_link(url, timeout=DEFAULT_TIMEOUT):
    """Preview a URL inside TinyFish's sandboxed browser.

    Args:
        url: the URL to visit.
        timeout: request timeout in seconds. Agent runs can take a while
            (real page load + reasoning), so this is deliberately higher
            than the Search/Fetch timeouts elsewhere in this project.

    Returns:
        dict with 'status' of 'not_configured' / 'failed' / 'unavailable'
        / 'success'. On 'success', also includes 'description',
        'has_login_form', 'requests_otp', and 'final_url'.
    """
    api_key = os.environ.get('TINYFISH_API_KEY')
    if not api_key:
        return {'status': 'not_configured'}
    if not url:
        return {'status': 'failed', 'message': 'No URL provided'}

    try:
        resp = requests.post(
            AGENT_URL,
            headers={'X-API-Key': api_key, 'Content-Type': 'application/json'},
            json={'url': url, 'goal': GOAL, 'browser_profile': 'lite'},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        run_status = data.get('status')
        if run_status != 'COMPLETED':
            return {'status': 'failed', 'message': run_status or 'unknown'}

        result = data.get('result') or {}
        return {
            'status': 'success',
            'description': result.get('description', ''),
            'has_login_form': bool(result.get('has_login_form')),
            'requests_otp': bool(result.get('requests_otp')),
            'final_url': result.get('final_url', url),
        }
    except requests.exceptions.RequestException as e:
        return {'status': 'unavailable', 'message': str(e)}
    except (ValueError, KeyError) as e:
        return {'status': 'unavailable', 'message': f'Unexpected response: {e}'}
