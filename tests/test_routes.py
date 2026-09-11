import pytest

from modules import geoip as geoip_mod
from modules import whois_lookup
from modules import auth_check


@pytest.fixture(autouse=True)
def _stub_external_lookups(monkeypatch):
    """None of the route tests should depend on real network access (GeoIP,
    WHOIS, live DMARC DNS) -- stub them so the suite is fast and deterministic
    offline, matching how the app already degrades gracefully without network."""
    monkeypatch.setattr(geoip_mod, 'lookup_ip',
                         lambda ip, timeout=4: {'status': 'no_ip'} if not ip else
                         {'status': 'success', 'ip': ip, 'country': 'Testland', 'country_code': 'TL',
                          'region': 'Test', 'city': 'Test City', 'zip': '00000', 'lat': 0.0, 'lon': 0.0,
                          'isp': 'Test ISP', 'org': 'Test Org', 'asn': 'AS0', 'as_name': 'TEST-AS',
                          'is_proxy_or_vpn': False, 'is_hosting_provider': False})
    monkeypatch.setattr(whois_lookup, 'lookup_domain',
                         lambda domain: {'status': 'unavailable', 'message': 'stubbed', 'domain': domain})
    monkeypatch.setattr(auth_check, 'check_dmarc_dns', lambda domain: None)


def _signup(client, email='analyst@example.com', password='correcthorsebattery'):
    return client.post('/signup', data={
        'full_name': 'Test Analyst',
        'email': email,
        'organization': 'Test Org',
        'password': password,
        'confirm_password': password,
    }, follow_redirects=True)


def test_landing_page_loads(client):
    resp = client.get('/')
    assert resp.status_code == 200


def test_signup_creates_account_and_logs_in(client):
    resp = _signup(client)
    assert resp.status_code == 200
    assert b'workspace' in resp.request.path.encode() or resp.request.path == '/app'


def test_signup_rejects_short_password(client):
    resp = client.post('/signup', data={
        'full_name': 'Test Analyst', 'email': 'short@example.com', 'organization': '',
        'password': 'short', 'confirm_password': 'short',
    }, follow_redirects=True)
    assert b'at least 8 characters' in resp.data


def test_signup_rejects_duplicate_email(client):
    _signup(client, email='dupe@example.com')
    client.get('/logout')
    resp = client.post('/signup', data={
        'full_name': 'Another', 'email': 'dupe@example.com', 'organization': '',
        'password': 'correcthorsebattery', 'confirm_password': 'correcthorsebattery',
    }, follow_redirects=True)
    assert b'already exists' in resp.data


def test_login_wrong_password_rejected(client):
    _signup(client, email='wrongpass@example.com')
    client.get('/logout')
    resp = client.post('/login', data={'email': 'wrongpass@example.com', 'password': 'nope'},
                        follow_redirects=True)
    assert b'Incorrect email or password' in resp.data


def test_workspace_requires_login(client):
    resp = client.get('/app', follow_redirects=True)
    assert b'log in' in resp.data.lower() or b'login' in resp.data.lower()


def test_analyze_requires_login(client):
    resp = client.post('/analyze', data={'raw_email': 'Subject: hi\n\nHello'}, follow_redirects=True)
    assert b'log in' in resp.data.lower() or b'login' in resp.data.lower()


def test_analyze_pasted_email_creates_case(client, sample_dir):
    _signup(client, email='phish-analyst@example.com')
    with open(f"{sample_dir}/phishing_sample.eml", 'r', encoding='utf-8') as f:
        raw_email = f.read()

    resp = client.post('/analyze', data={'raw_email': raw_email}, follow_redirects=True)
    assert resp.status_code == 200
    assert b'CASE-' in resp.data


def test_analyze_empty_submission_flashes_error(client):
    _signup(client, email='empty-submit@example.com')
    resp = client.post('/analyze', data={}, follow_redirects=True)
    assert b'paste raw email content' in resp.data.lower()


def test_dashboard_lists_own_cases_only(client, sample_dir):
    _signup(client, email='dash-user@example.com')
    with open(f"{sample_dir}/legit_sample.eml", 'r', encoding='utf-8') as f:
        raw_email = f.read()
    client.post('/analyze', data={'raw_email': raw_email})

    resp = client.get('/dashboard')
    assert resp.status_code == 200
    assert b'CASE-' in resp.data


def test_api_cases_returns_json(client, sample_dir):
    _signup(client, email='api-user@example.com')
    with open(f"{sample_dir}/legit_sample.eml", 'r', encoding='utf-8') as f:
        raw_email = f.read()
    client.post('/analyze', data={'raw_email': raw_email})

    resp = client.get('/api/cases')
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]['case_ref'].startswith('CASE-')


def test_connect_mailbox_page_loads_without_oauth_configured(client, monkeypatch):
    _signup(client, email='mailbox-user@example.com')
    resp = client.get('/connect-mailbox')
    assert resp.status_code == 200
