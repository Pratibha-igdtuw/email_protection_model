"""Tests for the API-key programmatic-access path (/api/cases via
X-API-Key), the security response headers applied to every response, and
the audit trail recorded for key user actions."""
import glob
import os
import re


def test_api_key_full_flow(client, sample_dir):
    # signup (session auth)
    r = client.post('/signup', data={'full_name': 'API User', 'email': 'apiuser@example.com',
                                      'organization': '', 'password': 'CorrectHorse1!',
                                      'confirm_password': 'CorrectHorse1!'}, follow_redirects=True)
    assert r.status_code == 200

    with open(f"{sample_dir}/legit_sample.eml") as f:
        raw_email = f.read()
    client.post('/analyze', data={'raw_email': raw_email})

    r = client.post('/account/api-key/generate', follow_redirects=True)
    m = re.search(rb'id="new-api-key"[^>]*>([^<]+)<', r.data)
    assert m, r.data
    raw_key = m.group(1).decode()

    client.get('/logout')

    r = client.get('/api/cases')
    assert r.status_code == 401

    r = client.get('/api/cases', headers={'X-API-Key': 'eptk_bogus'})
    assert r.status_code == 401

    r = client.get('/api/cases', headers={'X-API-Key': raw_key})
    assert r.status_code == 200, r.data
    data = r.get_json()
    assert len(data) == 1

    r = client.get('/dashboard', headers={'X-API-Key': raw_key})
    assert r.status_code in (302, 401)

    client.post('/login', data={'email': 'apiuser@example.com', 'password': 'CorrectHorse1!'})
    client.post('/account/api-key/revoke', follow_redirects=True)
    client.get('/logout')

    r = client.get('/api/cases', headers={'X-API-Key': raw_key})
    assert r.status_code == 401

def test_security_headers(client):
    r = client.get('/')
    for h in ('X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy', 'Referrer-Policy'):
        assert h in r.headers


def test_csp_allows_every_external_asset_domain_actually_used_by_templates(client):
    """Regression test for a real incident: the CSP shipped with
    script-src/style-src locked to 'self' while templates load Bootstrap,
    Font Awesome, Leaflet, and Google Fonts from cdnjs.cloudflare.com and
    fonts.googleapis.com. The browser doesn't error on a CSP violation --
    it silently drops the blocked CSS/JS, which looks exactly like "the
    whole layout is broken" with nothing informative in server logs. This
    scans every template for the https:// domains it actually references
    and fails loudly if the CSP header doesn't cover one of them, so this
    specific mistake can't reoccur unnoticed."""
    csp = client.get('/').headers['Content-Security-Policy']

    templates_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates')
    referenced_domains = set()
    for path in glob.glob(os.path.join(templates_dir, '**', '*.html'), recursive=True):
        with open(path, encoding='utf-8') as f:
            content = f.read()
        for m in re.finditer(r'(?:href|src)=["\']https://([^/"\']+)', content):
            referenced_domains.add(m.group(1))

    assert referenced_domains, "sanity check: template scan should have found at least one external domain"
    missing = {d for d in referenced_domains if d not in csp}
    assert not missing, f"CSP header doesn't allow-list domain(s) referenced by templates: {missing}"

def test_audit_log_recorded(client, sample_dir):
    client.post('/signup', data={'full_name': 'Audit User', 'email': 'audit@example.com',
                                  'organization': '', 'password': 'CorrectHorse1!',
                                  'confirm_password': 'CorrectHorse1!'}, follow_redirects=True)
    with open(f"{sample_dir}/legit_sample.eml") as f:
        raw_email = f.read()
    client.post('/analyze', data={'raw_email': raw_email})
    with client.application.app_context():
        from models import AuditLog
        actions = [a.action for a in AuditLog.query.all()]
    assert 'signup' in actions
    assert 'case_analyzed' in actions


def test_create_admin_cli_creates_new_admin(app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=['create-admin', 'clinewadmin@example.com',
                                  '--full-name', 'CLI Admin', '--password', 'CorrectHorse1!'])
    assert result.exit_code == 0
    with app.app_context():
        from models import User
        u = User.query.filter_by(email='clinewadmin@example.com').first()
        assert u is not None
        assert u.is_admin is True
        assert u.check_password('CorrectHorse1!')


def test_create_admin_cli_promotes_existing_user(app):
    with app.app_context():
        from models import User, db
        u = User(full_name='Existing User', email='clipromote@example.com')
        u.set_password('CorrectHorse1!')
        db.session.add(u)
        db.session.commit()
        assert u.is_admin is False

    runner = app.test_cli_runner()
    result = runner.invoke(args=['create-admin', 'clipromote@example.com'])
    assert result.exit_code == 0
    assert 'promoted to admin' in result.output

    with app.app_context():
        from models import User
        assert User.query.filter_by(email='clipromote@example.com').first().is_admin is True


def test_create_admin_cli_rejects_weak_password_for_new_account(app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=['create-admin', 'cliweak@example.com',
                                  '--full-name', 'Weak', '--password', 'short'])
    assert result.exit_code != 0
    with app.app_context():
        from models import User
        assert User.query.filter_by(email='cliweak@example.com').first() is None


def test_analyze_pipeline_timeouts_stay_within_5s_budget():
    """Regression test for a real incident: /analyze took ~18s in
    production because WHOIS/GeoIP/AbuseIPDB/DMARC-DNS timeouts were
    generous (6s/4s/4s/3s), and the concurrent pipeline's wall-clock time
    is bounded by whichever call is slowest. All four calls run
    concurrently (see app.py::run_pipeline), so the design invariant is
    "the largest single timeout, not the sum, stays under the ~5s
    end-to-end target" -- pinning each one individually would fight a
    deliberate later change (WHOIS was intentionally raised from 2s to 4s
    after 2s was cutting off genuinely-succeeding 2-hop referral lookups,
    not just slow ones -- see README "Analyze latency"). If any of these
    genuinely needs to grow further, update this test deliberately rather
    than letting the ceiling drift back toward the original incident."""
    import inspect

    from modules import whois_lookup, geoip, blacklist, auth_check

    geoip_default = inspect.signature(geoip.lookup_ip).parameters['timeout'].default
    abuseipdb_default = inspect.signature(blacklist.check_abuseipdb).parameters['timeout'].default
    dmarc_source = inspect.getsource(auth_check.check_dmarc_dns)
    m = re.search(r'lifetime=(\d+)', dmarc_source)
    dmarc_timeout = int(m.group(1)) if m else None

    # Individual sanity bounds -- none of the single-request lookups
    # (GeoIP/AbuseIPDB/DMARC) needs WHOIS's multi-hop-referral slack.
    assert geoip_default <= 2
    assert abuseipdb_default <= 2
    assert dmarc_timeout is not None and dmarc_timeout <= 2
    assert whois_lookup.WHOIS_TIMEOUT_SECONDS <= 4

    # The actual invariant that matters: since these run concurrently,
    # end-to-end worst case is the MAX of the four, not their sum. Leave
    # real headroom under 5s for local processing (classify, blacklist,
    # attachment/url scan, risk score, chain-of-custody + PDF generation)
    # and request/DB overhead, which measured well under 0.5s combined.
    worst_case = max(whois_lookup.WHOIS_TIMEOUT_SECONDS, geoip_default, abuseipdb_default, dmarc_timeout)
    assert worst_case <= 4.5, (
        f"largest single pipeline timeout is {worst_case}s -- concurrent "
        f"pipeline wall-clock time is bounded by this, not the sum, so "
        f"this alone would eat most/all of the ~5s /analyze budget"
    )