"""Regression tests for the 'Is this really their website?' check.

Real incident: brand "whatsapp" + link "delt.whatsapp.com" was reported as
the official site, and the 'official websites found' list included
google.com -- because the module trusted the top web-search results
blindly. These tests pin the fixed behaviour."""
from unittest import mock

import pytest

from modules import site_verification as sv


@pytest.fixture(autouse=True)
def _no_api_key_no_dns(monkeypatch):
    monkeypatch.delenv('TINYFISH_API_KEY', raising=False)
    # Never touch real DNS in tests: None == "unknown", the safe default.
    monkeypatch.setattr(sv, '_host_exists', lambda host, timeout=2: None)


def test_official_domain_passes_without_api_key():
    r = sv.verify_official_site('WhatsApp', 'https://www.whatsapp.com/download')
    assert r['status'] == 'success' and r['is_official'] is True


def test_result_shows_full_host_not_just_registrable_domain():
    r = sv.verify_official_site('whatsapp', 'delt.whatsapp.com')
    assert r['claimed_host'] == 'delt.whatsapp.com'
    assert r['is_official'] is True
    assert r['note'] and 'delt' in r['note']  # sub-address caution is shown


def test_nonexistent_subaddress_is_not_called_official(monkeypatch):
    monkeypatch.setattr(sv, '_host_exists', lambda host, timeout=2: False)
    r = sv.verify_official_site('whatsapp', 'delt.whatsapp.com')
    assert r['is_official'] is False
    assert 'does not exist' in r['verdict']


def test_unrelated_big_site_is_not_official_for_brand():
    r = sv.verify_official_site('WhatsApp', 'https://google.com')
    assert r['is_official'] is False
    assert 'google.com' not in r['official_domains'] or r['official_domains'][0] == 'whatsapp.com'


def test_search_results_that_are_not_the_brand_are_ignored(monkeypatch):
    monkeypatch.setenv('TINYFISH_API_KEY', 'k')
    fake = mock.Mock()
    fake.raise_for_status = lambda: None
    fake.json.return_value = {'results': [
        {'url': 'https://www.google.com/search?q=foobank'},
        {'url': 'https://en.wikipedia.org/wiki/Foobank'},
        {'url': 'https://www.foobank.com/'},
    ]}
    with mock.patch.object(sv.requests, 'get', return_value=fake):
        r = sv.verify_official_site('Foobank', 'https://google.com')
    assert r['official_domains'] == ['foobank.com']
    assert r['is_official'] is False


def test_search_finds_real_official_site(monkeypatch):
    monkeypatch.setenv('TINYFISH_API_KEY', 'k')
    fake = mock.Mock()
    fake.raise_for_status = lambda: None
    fake.json.return_value = {'results': [{'url': 'https://www.foobank.com/'}]}
    with mock.patch.object(sv.requests, 'get', return_value=fake):
        r = sv.verify_official_site('Foobank', 'https://www.foobank.com/login')
    assert r['is_official'] is True


def test_copycat_domain_is_called_out():
    r = sv.verify_official_site('WhatsApp', 'https://whatsap.com')
    assert r['is_official'] is False
    assert 'COPYCAT' in r['verdict'] and 'whatsapp.com' in r['verdict']


def test_brand_name_inside_a_different_domain_is_not_official():
    r = sv.verify_official_site('SBI', 'https://sbi-secure-login.example.com')
    assert r['is_official'] is False


def test_shared_hosting_subdomain_is_never_official():
    r = sv.verify_official_site('WhatsApp', 'https://whatsapp.github.io')
    assert r['is_official'] is False
    assert 'free hosting' in r['verdict']


def test_unknown_brand_without_api_key_reports_not_configured():
    assert sv.verify_official_site('Some Tiny Shop', 'https://x.com')['status'] == 'not_configured'


def test_missing_input():
    assert sv.verify_official_site('', 'https://x.com')['status'] == 'no_input'
