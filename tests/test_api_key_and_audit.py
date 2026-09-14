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
