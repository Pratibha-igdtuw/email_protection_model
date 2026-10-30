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
    # No network in tests: stub Wikidata and the reputation lookups (real
    # behaviour of those is covered in test_url_reputation.py).
    monkeypatch.setattr(sv.url_reputation, 'wikidata_official_domains',
                        lambda brand, timeout=5: {'status': 'unavailable'})
    monkeypatch.setattr(sv.url_reputation, 'gather_signals',
                        lambda url, host, domain, skip_age=False: {'signals': [], 'dangerous': False, 'threats': [], 'sources': {}})


def test_official_domain_passes_without_api_key():
    r = sv.verify_official_site('WhatsApp', 'https://www.whatsapp.com/download')
    assert r['status'] == 'success' and r['is_official'] is True


def test_unconfirmed_subaddress_is_not_passed_as_official():
    """delt.whatsapp.com: the domain is WhatsApp's, but anyone can type a
    made-up name in front of it. With DNS unable to confirm it, it must not
    be called official -- and the full address must be shown."""
    r = sv.verify_official_site('whatsapp', 'delt.whatsapp.com')
    assert r['claimed_host'] == 'delt.whatsapp.com'
    assert r['is_official'] is False
    assert 'Could NOT confirm' in r['verdict']


def test_confirmed_subaddress_is_official(monkeypatch):
    def fake(host, timeout=2):
        return not host.startswith('zz-')        # real name exists, random name does not
    monkeypatch.setattr(sv, '_host_exists', fake)
    r = sv.verify_official_site('whatsapp', 'web.whatsapp.com')
    assert r['is_official'] is True and r['note']


def test_wildcard_dns_does_not_prove_subaddress(monkeypatch):
    monkeypatch.setattr(sv, '_host_exists', lambda host, timeout=2: True)   # everything "exists"
    r = sv.verify_official_site('whatsapp', 'anything-goes.whatsapp.com')
    assert r['is_official'] is False


def test_bare_domain_and_www_need_no_dns():
    assert sv.verify_official_site('whatsapp', 'whatsapp.com')['is_official'] is True
    assert sv.verify_official_site('whatsapp', 'https://www.whatsapp.com/x')['is_official'] is True


def test_lookalike_search_results_are_not_accepted(monkeypatch):
    monkeypatch.setenv('TINYFISH_API_KEY', 'k')
    fake = mock.Mock()
    fake.raise_for_status = lambda: None
    fake.json.return_value = {'results': [
        {'url': 'https://foobank-login-help.com/'},
        {'url': 'https://foobank-secure.net/'},
        {'url': 'https://www.foobank.com/'},
    ]}
    with mock.patch.object(sv.requests, 'get', return_value=fake):
        r = sv.verify_official_site('Foobank', 'https://foobank-login-help.com')
    assert r['official_domains'] == ['foobank.com']
    assert r['is_official'] is False


def test_known_brand_ignores_search_results(monkeypatch):
    monkeypatch.setenv('TINYFISH_API_KEY', 'k')
    with mock.patch.object(sv.requests, 'get', side_effect=AssertionError('search must not be used')):
        r = sv.verify_official_site('WhatsApp', 'https://whatsapp-gold.com')
    assert r['is_official'] is False
    assert r['official_domains'][0] == 'whatsapp.com'


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


def test_unknown_brand_with_no_source_cannot_be_confirmed():
    r = sv.verify_official_site('Some Tiny Shop', 'https://x.com')
    assert r['status'] == 'success' and r['is_official'] is False
    assert 'Could not confirm' in r['verdict']


def test_wikidata_official_site_is_used_for_unknown_brand(monkeypatch):
    monkeypatch.setattr(sv.url_reputation, 'wikidata_official_domains',
                        lambda brand, timeout=5: {'status': 'success', 'domains': ['tinyshop.in'], 'entity': 'Tiny Shop'})
    ok = sv.verify_official_site('Tiny Shop', 'https://www.tinyshop.in/offers')
    assert ok['is_official'] is True and 'Wikidata' in ok['official_source']
    bad = sv.verify_official_site('Tiny Shop', 'https://tinyshop-offers.xyz')
    assert bad['is_official'] is False


def test_blacklist_hit_overrides_official_domain(monkeypatch):
    monkeypatch.setattr(sv.url_reputation, 'gather_signals',
                        lambda url, host, domain, skip_age=False: {
                            'signals': [{'name': 'safe_browsing', 'level': 'bad', 'text': 'listed'}],
                            'dangerous': True, 'threats': ['SOCIAL_ENGINEERING'], 'sources': {}})
    r = sv.verify_official_site('WhatsApp', 'https://whatsapp.com/abused-page')
    assert r['is_official'] is False and r['threat'] is True
    assert r['verdict'].startswith('DANGEROUS')


def test_missing_input():
    assert sv.verify_official_site('', 'https://x.com')['status'] == 'no_input'
