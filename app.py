import os
import io
import csv
import uuid
from datetime import datetime

from flask import (Flask, render_template, request, redirect, url_for,
                    flash, send_file, jsonify, Response)

from models import db, Case, BlacklistEntry, FeedbackLog
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
from modules import chain_of_custody
from modules import retrain as retrain_mod

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
REPORTS_DIR = os.path.join(BASE_DIR, 'case_reports')
os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(INSTANCE_DIR, 'threat_platform.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB

db.init_app(app)

with app.app_context():
    db.create_all()


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
    bl_score, bl_reasons = blacklist_mod.compute_blacklist_score(local_hits, abuseipdb_result)

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
        'blacklist_score': bl_score,
        'blacklist_reasons': bl_reasons,
        'risk_result': risk_result,
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
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
        return redirect(url_for('index'))

    return _analyze_and_render(raw_email_bytes)


def _analyze_and_render(raw_email_bytes):
    try:
        result = run_pipeline(raw_email_bytes)
    except Exception as e:
        flash(f'Failed to parse/analyze email: {e}', 'error')
        return redirect(url_for('index'))

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


@app.route('/report/<case_ref>')
def download_report(case_ref):
    case = Case.query.filter_by(case_ref=case_ref).first_or_404()
    if not case.report_path or not os.path.exists(case.report_path):
        flash('Report file not found.', 'error')
        return redirect(url_for('dashboard'))
    return send_file(case.report_path, as_attachment=True, download_name=f"{case_ref}_forensic_report.pdf")


@app.route('/dashboard')
def dashboard():
    q = request.args.get('q', '').strip()
    severity_filter = request.args.get('severity', '').strip()

    query = Case.query
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
def case_detail(case_ref):
    case = Case.query.filter_by(case_ref=case_ref).first_or_404()
    return render_template('case_detail.html', case=case)


@app.route('/case/<case_ref>/notes', methods=['POST'])
def update_notes(case_ref):
    case = Case.query.filter_by(case_ref=case_ref).first_or_404()
    case.analyst_notes = request.form.get('notes', '')
    db.session.commit()
    flash('Analyst notes saved.', 'success')
    return redirect(url_for('case_detail', case_ref=case_ref))


@app.route('/dashboard/export.csv')
def export_csv():
    cases = Case.query.order_by(Case.created_at.desc()).all()
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
def api_cases():
    cases = Case.query.order_by(Case.created_at.desc()).all()
    return jsonify([c.to_dict() for c in cases])


# ---------------------------------------------------------------------------
# USP 2 + 5: Geolocation clustering + Interactive Threat Map Dashboard
# ---------------------------------------------------------------------------
@app.route('/dashboard/map')
def threat_map():
    cases = Case.query.filter(Case.latitude.isnot(None), Case.longitude.isnot(None)).all()
    summary = clustering.repeat_offender_summary(Case.query.all())
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
def threat_clusters():
    all_cases = Case.query.order_by(Case.created_at.desc()).all()
    clusters = clustering.build_clusters(all_cases)
    return render_template('clusters.html', clusters=clusters)


# ---------------------------------------------------------------------------
# USP 6: Lightweight Gmail / Outlook / Exchange (IMAP) integration
# ---------------------------------------------------------------------------
@app.route('/connect-mailbox', methods=['GET'])
def connect_mailbox():
    return render_template('connect_mailbox.html')


@app.route('/connect-mailbox/fetch', methods=['POST'])
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

    previews = []
    for idx, raw in enumerate(result['emails']):
        p = mailbox_connector.quick_preview(raw)
        p['index'] = idx
        previews.append(p)

    # Stash raw bytes in a short-lived server-side cache file per session-less demo use
    cache_dir = os.path.join(REPORTS_DIR, '_mailbox_cache')
    os.makedirs(cache_dir, exist_ok=True)
    batch_id = uuid.uuid4().hex[:10]
    for idx, raw in enumerate(result['emails']):
        with open(os.path.join(cache_dir, f"{batch_id}_{idx}.eml"), 'wb') as f:
            f.write(raw)

    return render_template('mailbox_picker.html', previews=previews, batch_id=batch_id, count=result['count'])


@app.route('/connect-mailbox/analyze/<batch_id>/<int:index>')
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
def submit_feedback(case_ref):
    case = Case.query.filter_by(case_ref=case_ref).first_or_404()
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
    app.run(debug=True, host='0.0.0.0', port=5000)