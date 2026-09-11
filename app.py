import os
import io
import csv
import uuid
import logging
from datetime import datetime

from flask import (Flask, render_template, request, redirect, url_for,
                    flash, send_file, jsonify, Response, abort, session)
from flask_login import (LoginManager, login_user, logout_user, login_required,
                          current_user)
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import get_config
from models import db, User, Case, BlacklistEntry, FeedbackLog, MailboxOAuthToken
from modules import parser as parser_mod
from modules import auth_check
from modules import geoip as geoip_mod
from modules import whois_lookup
from modules import classifier
from modules import blacklist as blacklist_mod
from modules import risk_score
from modules import report_gen
from modules import clustering
from modules import mailbox_connector
from modules import oauth_gmail
from modules import chain_of_custody
from modules import retrain as retrain_mod
from modules import blacklist as blacklist_freshness_mod

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
REPORTS_DIR = os.path.join(BASE_DIR, 'case_reports')
os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('email_threat_platform')

app = Flask(__name__)
app.config.from_object(get_config())

csrf = CSRFProtect(app)

db.init_app(app)
migrate = Migrate(app, db)  # `flask db migrate` / `flask db upgrade` -- see README

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=app.config.get('RATELIMIT_STORAGE_URI', 'memory://'),
    enabled=app.config.get('RATELIMIT_ENABLED', True),
    default_limits=[],  # only the routes below are limited; everything else is unlimited
)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to continue.'
login_manager.login_message_category = 'error'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


if app.config.get('AUTO_CREATE_TABLES'):
    # Dev/test convenience only. Production deployments use Flask-Migrate:
    #   flask db upgrade
    # See README "Database migrations".
    with app.app_context():
        db.create_all()

_freshness = blacklist_freshness_mod.get_phishtank_freshness()
if _freshness['stale']:
    logger.warning(
        "PhishTank domain snapshot is stale (last refreshed: %s, age: %s days). "
        "Run `python ml_model/refresh_phishtank.py` to update it -- see README "
        "'Keeping PhishTank data fresh'.",
        _freshness['last_refreshed_at'], _freshness['age_days'],
    )


def run_pipeline(raw_email_bytes):
    """Runs the full unified analysis pipeline on raw email content."""
    parsed = parser_mod.parse_email(raw_email_bytes)
    urls = parser_mod.extract_urls(parsed.get('body_plain', '') + ' ' + parsed.get('body_html', ''))

    auth_result = auth_check.run_authentication_check(parsed)
    geo_result = geoip_mod.lookup_ip(parsed.get('originating_ip'))
    geo_mismatch = geoip_mod.check_brand_mismatch(parsed.get('sender_domain'), geo_result)
    whois_result = whois_lookup.lookup_domain(parsed.get('sender_domain'))
    classify_result = classifier.classify_email(parsed, urls)

    local_hits = blacklist_mod.check_local_blacklist(
        parsed.get('originating_ip'), parsed.get('sender_domain'), db.session, BlacklistEntry
    )
    abuseipdb_result = blacklist_mod.check_abuseipdb(parsed.get('originating_ip'))
    phishtank_result = blacklist_mod.check_phishtank(parsed.get('sender_domain'), urls)
    bl_score, bl_reasons = blacklist_mod.compute_blacklist_score(local_hits, abuseipdb_result, phishtank_result)

    risk_result = risk_score.compute_combined_score(
        classify_result, auth_result, geo_mismatch, whois_result, bl_score
    )

    return {
        'parsed_email': parsed,
        'urls': urls,
        'auth_result': auth_result,
        'geo_result': geo_result,
        'geo_mismatch': geo_mismatch,
        'whois_result': whois_result,
        'classify_result': classify_result,
        'local_blacklist_hits': local_hits,
        'abuseipdb_result': abuseipdb_result,
        'phishtank_result': phishtank_result,
        'blacklist_score': bl_score,
        'blacklist_reasons': bl_reasons,
        'risk_result': risk_result,
    }


@app.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('workspace'))
    return render_template('landing.html')


@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('workspace'))

    form = {'full_name': '', 'email': '', 'organization': ''}
    if request.method == 'POST':
        form['full_name'] = request.form.get('full_name', '').strip()
        form['email'] = request.form.get('email', '').strip().lower()
        form['organization'] = request.form.get('organization', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not form['full_name'] or not form['email'] or not password:
            flash('Name, work email and password are required.', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
        elif password != confirm:
            flash('Passwords do not match.', 'error')
        elif User.query.filter_by(email=form['email']).first():
            flash('An account with that email already exists — log in instead.', 'error')
        else:
            user = User(full_name=form['full_name'], email=form['email'],
                        organization=form['organization'] or None)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash(f"Welcome, {user.full_name.split()[0]} — your workspace is ready.", 'success')
            return redirect(url_for('workspace'))

    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("15 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('workspace'))

    email = ''
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))
        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            flash('Incorrect email or password.', 'error')
        else:
            login_user(user, remember=remember)
            flash(f"Welcome back, {user.full_name.split()[0]}.", 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('workspace'))

    return render_template('login.html', email=email)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('landing'))


@app.route('/app')
@login_required
def workspace():
    return render_template('workspace.html')


@app.route('/analyze', methods=['POST'])
@login_required
@limiter.limit("30 per hour")
def analyze():
    raw_email_bytes = None
    if 'eml_file' in request.files and request.files['eml_file'].filename:
        f = request.files['eml_file']
        raw_email_bytes = f.read()
    else:
        pasted = request.form.get('raw_email', '').strip()
        if pasted:
            raw_email_bytes = pasted.encode('utf-8')

    if not raw_email_bytes:
        flash('Please paste raw email content or upload a .eml file.', 'error')
        return redirect(url_for('workspace'))

    return _analyze_and_render(raw_email_bytes)


def _analyze_and_render(raw_email_bytes):
    try:
        result = run_pipeline(raw_email_bytes)
    except Exception as e:
        flash(f'Failed to parse/analyze email: {e}', 'error')
        return redirect(url_for('workspace'))

    case_ref = f"CASE-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    # Save raw email + compute chain-of-custody hash at ingestion time
    raw_path = os.path.join(REPORTS_DIR, f"{case_ref}.eml")
    with open(raw_path, 'wb') as fh:
        fh.write(raw_email_bytes)
    evidence_hash = chain_of_custody.compute_sha256(raw_email_bytes)

    parsed = result['parsed_email']
    risk = result['risk_result']
    auth = result['auth_result']
    geo = result['geo_result']

    case = Case(
        owner_id=current_user.id,
        case_ref=case_ref,
        subject=parsed.get('subject'),
        sender_from=parsed.get('from_raw'),
        sender_domain=parsed.get('sender_domain'),
        originating_ip=parsed.get('originating_ip'),
        combined_score=risk['combined_score'],
        severity=risk['severity'],
        ml_probability=result['classify_result']['ml_probability'],
        spf_result=auth['spf'],
        dkim_result=auth['dkim'],
        dmarc_result=auth['dmarc'],
        country=geo.get('country') if geo.get('status') == 'success' else None,
        latitude=geo.get('lat') if geo.get('status') == 'success' else None,
        longitude=geo.get('lon') if geo.get('status') == 'success' else None,
        asn=geo.get('asn') if geo.get('status') == 'success' else None,
        isp=geo.get('isp') if geo.get('status') == 'success' else None,
        evidence_sha256=evidence_hash,
        hash_generated_at=datetime.utcnow(),
        body_text=f"{parsed.get('subject','')} {parsed.get('body_plain','')}"[:5000],
        raw_email_path=raw_path,
    )
    db.session.add(case)
    db.session.commit()

    # Generate PDF report (includes chain-of-custody block)
    custody_record = chain_of_custody.build_custody_record(case_ref, raw_path, evidence_hash)
    report_path = os.path.join(REPORTS_DIR, f"{case_ref}.pdf")
    pipeline_case = {**result, 'case_id': case_ref, 'custody_record': custody_record}
    report_gen.generate_pdf_report(pipeline_case, report_path)
    case.report_path = report_path
    db.session.commit()

    return render_template('result.html', case_ref=case_ref, result=result, case=case)


def _get_owned_case_or_404(case_ref):
    case = Case.query.filter_by(case_ref=case_ref).first_or_404()
    if case.owner_id is not None and case.owner_id != current_user.id:
        abort(404)
    return case


@app.route('/report/<case_ref>')
@login_required
def download_report(case_ref):
    case = _get_owned_case_or_404(case_ref)
    if not case.report_path or not os.path.exists(case.report_path):
        flash('Report file not found.', 'error')
        return redirect(url_for('dashboard'))
    return send_file(case.report_path, as_attachment=True, download_name=f"{case_ref}_forensic_report.pdf")


@app.route('/dashboard')
@login_required
def dashboard():
    q = request.args.get('q', '').strip()
    severity_filter = request.args.get('severity', '').strip()

    query = Case.query.filter_by(owner_id=current_user.id)
    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(Case.subject.ilike(like), Case.sender_from.ilike(like),
                   Case.sender_domain.ilike(like), Case.case_ref.ilike(like))
        )
    if severity_filter:
        query = query.filter_by(severity=severity_filter)

    cases = query.order_by(Case.created_at.desc()).all()
    return render_template('dashboard.html', cases=cases, q=q, severity_filter=severity_filter)


@app.route('/case/<case_ref>')
@login_required
def case_detail(case_ref):
    case = _get_owned_case_or_404(case_ref)
    return render_template('case_detail.html', case=case)


@app.route('/case/<case_ref>/notes', methods=['POST'])
@login_required
def update_notes(case_ref):
    case = _get_owned_case_or_404(case_ref)
    case.analyst_notes = request.form.get('notes', '')
    db.session.commit()
    flash('Analyst notes saved.', 'success')
    return redirect(url_for('case_detail', case_ref=case_ref))


@app.route('/dashboard/export.csv')
@login_required
def export_csv():
    cases = Case.query.filter_by(owner_id=current_user.id).order_by(Case.created_at.desc()).all()
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['Case Ref', 'Subject', 'From', 'Domain', 'IP', 'Score', 'Severity',
                      'SPF', 'DKIM', 'DMARC', 'Country', 'Created At'])
    for c in cases:
        writer.writerow([c.case_ref, c.subject, c.sender_from, c.sender_domain, c.originating_ip,
                          c.combined_score, c.severity, c.spf_result, c.dkim_result, c.dmarc_result,
                          c.country, c.created_at])
    return Response(si.getvalue(), mimetype='text/csv',
                     headers={'Content-Disposition': 'attachment; filename=case_history.csv'})


@app.route('/api/cases')
@login_required
def api_cases():
    cases = Case.query.filter_by(owner_id=current_user.id).order_by(Case.created_at.desc()).all()
    return jsonify([c.to_dict() for c in cases])


# ---------------------------------------------------------------------------
# USP 2 + 5: Geolocation clustering + Interactive Threat Map Dashboard
# ---------------------------------------------------------------------------
@app.route('/dashboard/map')
@login_required
def threat_map():
    own_cases = Case.query.filter_by(owner_id=current_user.id)
    cases = own_cases.filter(Case.latitude.isnot(None), Case.longitude.isnot(None)).all()
    summary = clustering.repeat_offender_summary(own_cases.all())
    markers = [{
        'case_ref': c.case_ref,
        'lat': c.latitude,
        'lon': c.longitude,
        'severity': c.severity,
        'score': c.combined_score,
        'country': c.country,
        'isp': c.isp,
        'domain': c.sender_domain,
        'subject': (c.subject or '')[:80],
    } for c in cases]
    return render_template('map.html', markers=markers, summary=summary)


@app.route('/dashboard/clusters')
@login_required
def threat_clusters():
    all_cases = Case.query.filter_by(owner_id=current_user.id).order_by(Case.created_at.desc()).all()
    clusters = clustering.build_clusters(all_cases)
    return render_template('clusters.html', clusters=clusters)


# ---------------------------------------------------------------------------
# USP 6: Lightweight Gmail / Outlook / Exchange (IMAP) integration
# ---------------------------------------------------------------------------
@app.route('/connect-mailbox', methods=['GET'])
@login_required
def connect_mailbox():
    return render_template('connect_mailbox.html', gmail_oauth_available=oauth_gmail.is_configured())


def _cache_emails_and_render_picker(raw_emails):
    """Shared by both the IMAP app-password path and the Gmail OAuth path:
    caches fetched raw messages server-side and renders the picker UI."""
    previews = []
    for idx, raw in enumerate(raw_emails):
        p = mailbox_connector.quick_preview(raw)
        p['index'] = idx
        previews.append(p)

    cache_dir = os.path.join(REPORTS_DIR, '_mailbox_cache')
    os.makedirs(cache_dir, exist_ok=True)
    batch_id = uuid.uuid4().hex[:10]
    for idx, raw in enumerate(raw_emails):
        with open(os.path.join(cache_dir, f"{batch_id}_{idx}.eml"), 'wb') as f:
            f.write(raw)

    return render_template('mailbox_picker.html', previews=previews, batch_id=batch_id, count=len(raw_emails))


@app.route('/connect-mailbox/fetch', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def connect_mailbox_fetch():
    provider = request.form.get('provider', 'gmail')
    username = request.form.get('username', '').strip()
    app_password = request.form.get('app_password', '').strip()
    limit = int(request.form.get('limit', 10))

    if not username or not app_password:
        flash('Email address and app password are required.', 'error')
        return redirect(url_for('connect_mailbox'))

    result = mailbox_connector.fetch_recent_emails(provider, username, app_password, limit=limit)
    if result['status'] != 'success':
        flash(f"Mailbox connection failed: {result['message']}", 'error')
        return redirect(url_for('connect_mailbox'))

    return _cache_emails_and_render_picker(result['emails'])


# ---------------------------------------------------------------------------
# Gmail OAuth2 connector (upgrade over the IMAP app-password path above,
# for accounts that can use it -- see modules/oauth_gmail.py)
# ---------------------------------------------------------------------------
@app.route('/connect-mailbox/oauth/start')
@login_required
def connect_mailbox_oauth_start():
    if not oauth_gmail.is_configured():
        flash('Gmail OAuth is not configured on this server. Ask your administrator to set '
              'GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET / GOOGLE_OAUTH_REDIRECT_URI, '
              'or use the app-password option below.', 'error')
        return redirect(url_for('connect_mailbox'))

    state = uuid.uuid4().hex
    session['gmail_oauth_state'] = state
    return redirect(oauth_gmail.build_auth_url(state))


@app.route('/connect-mailbox/oauth/callback')
@login_required
@limiter.limit("10 per hour")
def connect_mailbox_oauth_callback():
    error = request.args.get('error')
    if error:
        flash(f'Google declined the connection request: {error}', 'error')
        return redirect(url_for('connect_mailbox'))

    state = request.args.get('state')
    if not state or state != session.pop('gmail_oauth_state', None):
        flash('OAuth state mismatch -- please try connecting again.', 'error')
        return redirect(url_for('connect_mailbox'))

    code = request.args.get('code')
    if not code:
        flash('No authorization code returned by Google.', 'error')
        return redirect(url_for('connect_mailbox'))

    try:
        token_data = oauth_gmail.exchange_code_for_token(code)
    except Exception as e:
        flash(f'Failed to complete Gmail authorization: {e}', 'error')
        return redirect(url_for('connect_mailbox'))

    token_row = MailboxOAuthToken.query.filter_by(user_id=current_user.id, provider='gmail').first()
    if token_row is None:
        token_row = MailboxOAuthToken(user_id=current_user.id, provider='gmail')
        db.session.add(token_row)

    token_row.access_token = token_data['access_token']
    # Google only returns a refresh_token on first consent; keep the existing
    # one if this is a re-connect without a fresh refresh_token.
    if token_data.get('refresh_token'):
        token_row.refresh_token = token_data['refresh_token']
    token_row.token_expiry = token_data.get('token_expiry')
    token_row.scope = token_data.get('scope')
    db.session.commit()

    try:
        mailbox_email, _ = oauth_gmail.get_mailbox_email(token_row)
        token_row.mailbox_email = mailbox_email
        db.session.commit()
    except Exception:
        pass  # cosmetic only -- fetch below will surface any real auth problem

    flash(f"Connected Gmail account{' (' + token_row.mailbox_email + ')' if token_row.mailbox_email else ''}.",
          'success')
    return redirect(url_for('connect_mailbox_oauth_fetch'))


@app.route('/connect-mailbox/oauth/fetch')
@login_required
@limiter.limit("10 per hour")
def connect_mailbox_oauth_fetch():
    token_row = MailboxOAuthToken.query.filter_by(user_id=current_user.id, provider='gmail').first()
    if token_row is None:
        flash('No connected Gmail account found -- connect one first.', 'error')
        return redirect(url_for('connect_mailbox'))

    limit = int(request.args.get('limit', 10))
    result = oauth_gmail.fetch_recent_emails(token_row, limit=limit)
    if result.get('refreshed_token'):
        token_row.access_token = result['refreshed_token']['access_token']
        token_row.token_expiry = result['refreshed_token']['token_expiry']
        db.session.commit()

    if result['status'] != 'success':
        flash(f"Gmail fetch failed: {result['message']}", 'error')
        return redirect(url_for('connect_mailbox'))

    return _cache_emails_and_render_picker(result['emails'])


@app.route('/connect-mailbox/oauth/disconnect', methods=['POST'])
@login_required
def connect_mailbox_oauth_disconnect():
    MailboxOAuthToken.query.filter_by(user_id=current_user.id, provider='gmail').delete()
    db.session.commit()
    flash('Disconnected Gmail account.', 'success')
    return redirect(url_for('connect_mailbox'))


@app.route('/connect-mailbox/analyze/<batch_id>/<int:index>')
@login_required
def connect_mailbox_analyze(batch_id, index):
    cache_dir = os.path.join(REPORTS_DIR, '_mailbox_cache')
    path = os.path.join(cache_dir, f"{batch_id}_{index}.eml")
    if not os.path.exists(path):
        flash('This fetched email is no longer available — please reconnect and fetch again.', 'error')
        return redirect(url_for('connect_mailbox'))
    with open(path, 'rb') as f:
        raw_email_bytes = f.read()
    return _analyze_and_render(raw_email_bytes)


# ---------------------------------------------------------------------------
# USP 7: Self-improving model — analyst feedback loop
# ---------------------------------------------------------------------------
@app.route('/case/<case_ref>/feedback', methods=['POST'])
@login_required
def submit_feedback(case_ref):
    case = _get_owned_case_or_404(case_ref)
    verdict = request.form.get('verdict')
    if verdict not in ('Confirmed Phishing', 'False Positive'):
        flash('Invalid verdict.', 'error')
        return redirect(url_for('case_detail', case_ref=case_ref))

    case.analyst_verdict = verdict
    label = 1 if verdict == 'Confirmed Phishing' else 0
    retrain_mod.add_feedback_example(case.body_text or case.subject or '', label)
    db.session.add(FeedbackLog(case_ref=case_ref, verdict=verdict))
    db.session.commit()

    flash(f'Feedback recorded ({verdict}). This example will be used next time the model is retrained.', 'success')
    return redirect(url_for('case_detail', case_ref=case_ref))


@app.route('/retrain-model', methods=['POST'])
@login_required
@limiter.limit("5 per hour")
def retrain_model():
    result = retrain_mod.retrain_with_feedback()
    if result['status'] == 'success':
        classifier.reload_model()
        FeedbackLog.query.update({'used_in_training': True})
        db.session.commit()
        flash(f"Model retrained on {result['total_samples']} samples "
              f"({result['feedback_samples']} from analyst feedback).", 'success')
    else:
        flash(f"Retraining skipped: {result['message']}", 'error')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    # Local/dev use only. For production, run behind a real WSGI server:
    #   gunicorn -c gunicorn.conf.py wsgi:application
    # See README "Deploying to production".
    app.run(debug=app.config.get('DEBUG', False), host='0.0.0.0', port=5000)