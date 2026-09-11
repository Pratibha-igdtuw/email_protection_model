import json
from datetime import datetime, timedelta, timezone

import pytest

from modules import blacklist


def test_compute_blacklist_score_no_hits():
    score, reasons = blacklist.compute_blacklist_score([], {'status': 'not_configured'}, None)
    assert score == 0
    assert reasons == []


def test_compute_blacklist_score_local_hit():
    local_hits = [{'indicator': '1.2.3.4', 'type': 'ip', 'reason': 'known spam relay'}]
    score, reasons = blacklist.compute_blacklist_score(local_hits, {'status': 'not_configured'}, None)
    assert score > 0
    assert any('local blacklist' in r.lower() for r in reasons)


def test_compute_blacklist_score_phishtank_hit():
    phishtank_result = {'hits': [{'domain': 'evil.example', 'target': 'PayPal', 'verified_time': '2026-01-01'}]}
    score, reasons = blacklist.compute_blacklist_score([], {'status': 'not_configured'}, phishtank_result)
    assert score > 0
    assert any('PhishTank' in r for r in reasons)


def test_check_phishtank_matches_sender_domain(monkeypatch):
    monkeypatch.setattr(blacklist, '_phishtank_domains', {
        'evil.example': {'target': 'PayPal', 'verified_time': '2026-01-01T00:00:00+00:00'}
    })
    monkeypatch.setattr(blacklist, '_load_phishtank_domains', lambda: blacklist._phishtank_domains)
    monkeypatch.setattr(blacklist, 'get_phishtank_freshness',
                         lambda: {'last_refreshed_at': None, 'age_days': None, 'stale': False})

    result = blacklist.check_phishtank('evil.example', [])
    assert result['status'] == 'checked'
    assert len(result['hits']) == 1
    assert result['hits'][0]['domain'] == 'evil.example'


def test_check_phishtank_matches_url_host(monkeypatch):
    monkeypatch.setattr(blacklist, '_phishtank_domains', {
        'evil.example': {'target': 'PayPal', 'verified_time': '2026-01-01T00:00:00+00:00'}
    })
    monkeypatch.setattr(blacklist, '_load_phishtank_domains', lambda: blacklist._phishtank_domains)
    monkeypatch.setattr(blacklist, 'get_phishtank_freshness',
                         lambda: {'last_refreshed_at': None, 'age_days': None, 'stale': False})

    result = blacklist.check_phishtank('safe-sender.com', ['http://evil.example/verify'])
    assert len(result['hits']) == 1


def test_get_phishtank_freshness_flags_stale(monkeypatch, tmp_path):
    old_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    meta_path = tmp_path / 'phishtank_metadata.json'
    meta_path.write_text(json.dumps({'last_refreshed_at': old_time}))

    monkeypatch.setattr(blacklist, '_phishtank_metadata', None)
    monkeypatch.setattr(blacklist, 'PHISHTANK_METADATA_PATH', str(meta_path))

    freshness = blacklist.get_phishtank_freshness()
    assert freshness['stale'] is True
    assert freshness['age_days'] > blacklist.PHISHTANK_STALE_AFTER_DAYS


def test_get_phishtank_freshness_flags_fresh(monkeypatch, tmp_path):
    recent_time = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    meta_path = tmp_path / 'phishtank_metadata.json'
    meta_path.write_text(json.dumps({'last_refreshed_at': recent_time}))

    monkeypatch.setattr(blacklist, '_phishtank_metadata', None)
    monkeypatch.setattr(blacklist, 'PHISHTANK_METADATA_PATH', str(meta_path))

    freshness = blacklist.get_phishtank_freshness()
    assert freshness['stale'] is False


def test_get_phishtank_freshness_missing_metadata(monkeypatch, tmp_path):
    monkeypatch.setattr(blacklist, '_phishtank_metadata', None)
    monkeypatch.setattr(blacklist, 'PHISHTANK_METADATA_PATH', str(tmp_path / 'does_not_exist.json'))

    freshness = blacklist.get_phishtank_freshness()
    assert freshness['stale'] is True
    assert freshness['last_refreshed_at'] is None


def test_check_abuseipdb_not_configured(monkeypatch):
    monkeypatch.delenv('ABUSEIPDB_API_KEY', raising=False)
    result = blacklist.check_abuseipdb('1.2.3.4')
    assert result['status'] == 'not_configured'
