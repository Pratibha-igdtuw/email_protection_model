"""
Refreshes the bundled PhishTank-verified phishing domain snapshot
(ml_model/phishtank_domains.csv) from PhishTank's live feed, and stamps
ml_model/phishtank_metadata.json with the refresh time so the app can warn
analysts when the snapshot is going stale (see modules/blacklist.py,
PHISHTANK_STALE_AFTER_DAYS).

This is the fix for "PhishTank data is a static snapshot, not a live feed
-- will silently go stale": the snapshot itself is still a snapshot (there
is no free real-time PhishTank API), but it is no longer *silent* about
its own age, and this script gives you a one-command way to update it.

PhishTank requires a (free) API key for the bulk data feed as of their
current terms. Set it via the PHISHTANK_API_KEY env var:
    export PHISHTANK_API_KEY=your_key_here
    python ml_model/refresh_phishtank.py

Recommended: run this on a schedule (weekly cron job / CI scheduled
workflow) rather than only by hand -- see README "Keeping PhishTank data
fresh" for a sample cron line and GitHub Actions schedule.

Run:  python ml_model/refresh_phishtank.py
"""
import os
import csv
import sys
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_CSV = os.path.join(HERE, 'phishtank_domains.csv')
METADATA_PATH = os.path.join(HERE, 'phishtank_metadata.json')

# PhishTank's online-valid feed, keyed by API key. Format=json for easy parsing.
FEED_URL_TEMPLATE = "https://data.phishtank.com/data/{api_key}/online-valid.json"

csv.field_size_limit(sys.maxsize)


def _domain_from_url(url):
    try:
        from urllib.parse import urlparse
        host = urlparse(url).netloc.split(':')[0].lower()
        return host or None
    except Exception:
        return None


def fetch_live_feed(api_key, timeout=30, retries=3):
    url = FEED_URL_TEMPLATE.format(api_key=api_key)
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'email-threat-platform-refresh/1.0'})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            last_err = e
            print(f"Attempt {attempt}/{retries} failed: {e}", file=sys.stderr)
            time.sleep(2 * attempt)
    raise RuntimeError(f"Could not fetch PhishTank feed after {retries} attempts: {last_err}")


def write_snapshot(entries):
    """entries: iterable of dicts with 'domain', 'target', 'verified_time'."""
    deduped = {}
    for e in entries:
        d = (e.get('domain') or '').strip().lower()
        if not d:
            continue
        deduped[d] = {'domain': d, 'target': e.get('target') or 'Other',
                      'verified_time': e.get('verified_time')}

    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['domain', 'target', 'verified_time'])
        w.writeheader()
        w.writerows(deduped.values())

    now_iso = datetime.now(timezone.utc).isoformat()
    with open(METADATA_PATH, 'w', encoding='utf-8') as f:
        json.dump({
            'source': 'PhishTank (https://phishtank.org) verified phishing feed',
            'last_refreshed_at': now_iso,
            'entry_count': len(deduped),
        }, f, indent=2)

    return len(deduped), now_iso


def main():
    api_key = os.environ.get('PHISHTANK_API_KEY')
    if not api_key:
        print("PHISHTANK_API_KEY is not set. Get a free key from https://www.phishtank.com/api_register.php "
              "and export it before running this script.", file=sys.stderr)
        sys.exit(1)

    print("Fetching live PhishTank feed...")
    raw_entries = fetch_live_feed(api_key)

    entries = []
    for item in raw_entries:
        if not item.get('verified') or str(item.get('verified')).lower() not in ('yes', 'true'):
            continue
        url = item.get('url', '')
        domain = _domain_from_url(url)
        if not domain:
            continue
        target = (item.get('target') or 'Other')
        verified_time = item.get('verification_time') or item.get('submission_time')
        entries.append({'domain': domain, 'target': target, 'verified_time': verified_time})

    count, refreshed_at = write_snapshot(entries)
    print(f"Wrote {count} verified phishing domains to {OUTPUT_CSV}")
    print(f"Stamped {METADATA_PATH} with last_refreshed_at = {refreshed_at}")


if __name__ == '__main__':
    main()
