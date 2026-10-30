"""Tests for the accuracy-focused checks added to the website, image and
phone tools: URL reputation (Safe Browsing / VirusTotal / Wikidata / lexical
signals), image provenance (C2PA / reverse search / AI detector), phone
intelligence (libphonenumber / Veriphone) and the call scam-script analyzer.
All network calls are mocked -- the suite stays offline and deterministic."""
import io
from unittest import mock

import pytest
from PIL import Image

from modules import image_provenance as ip
from modules import phone_intel as pi
from modules import scam_script as ss
from modules import url_reputation as ur


def _resp(json_data=None, status=200):
    r = mock.Mock()
    r.status_code = status
    r.json.return_value = json_data if json_data is not None else {}
    r.raise_for_status = lambda: None if status < 400 else (_ for _ in ()).throw(ur.requests.exceptions.HTTPError(str(status)))
    return r


# ----------------------------------------------------------- url_reputation
def test_lexical_signals_flag_punycode_ip_at_and_http():
    sig = {s['name'] for s in ur.lexical_signals('http://xn--pypal-4ve.com/login', 'xn--pypal-4ve.com')}
    assert {'punycode', 'no_https'} <= sig
    assert 'ip_host' in {s['name'] for s in ur.lexical_signals('https://192.168.4.4/x', '192.168.4.4')}
    assert 'at_sign' in {s['name'] for s in ur.lexical_signals('https://paypal.com@evil.top/', 'evil.top')}
    assert 'tld' in {s['name'] for s in ur.lexical_signals('https://x.xyz', 'x.xyz')}


def test_lexical_signals_quiet_for_normal_https_site():
    assert ur.lexical_signals('https://www.sbi.co.in/', 'www.sbi.co.in') == []


def test_safe_browsing_not_configured_without_key(monkeypatch):
    monkeypatch.delenv('GOOGLE_SAFE_BROWSING_API_KEY', raising=False)
    assert ur.google_safe_browsing('https://x.com')['status'] == 'not_configured'


def test_safe_browsing_reports_threat_types(monkeypatch):
    monkeypatch.setenv('GOOGLE_SAFE_BROWSING_API_KEY', 'k')
    with mock.patch.object(ur.requests, 'post', return_value=_resp({'matches': [{'threatType': 'SOCIAL_ENGINEERING'}]})):
        assert ur.google_safe_browsing('https://bad.example')['threats'] == ['SOCIAL_ENGINEERING']
    with mock.patch.object(ur.requests, 'post', return_value=_resp({})):
        assert ur.google_safe_browsing('https://fine.example')['threats'] == []


def test_virustotal_counts(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'k')
    body = {'data': {'attributes': {'last_analysis_stats': {'malicious': 7, 'suspicious': 1, 'harmless': 60}}}}
    with mock.patch.object(ur.requests, 'get', return_value=_resp(body)):
        r = ur.virustotal('https://bad.example')
    assert r['malicious'] == 7 and r['known'] is True
    with mock.patch.object(ur.requests, 'get', return_value=_resp({}, 404)):
        assert ur.virustotal('https://new.example')['known'] is False


def test_gather_signals_marks_blacklisted_link_dangerous(monkeypatch):
    monkeypatch.setattr(ur, 'google_safe_browsing', lambda url, timeout=5: {'status': 'success', 'threats': ['MALWARE']})
    monkeypatch.setattr(ur, 'virustotal', lambda url, timeout=5: {'status': 'not_configured'})
    monkeypatch.setattr(ur, 'domain_age_signal', lambda d: None)
    out = ur.gather_signals('https://bad.example', 'bad.example', 'bad.example')
    assert out['dangerous'] is True and 'MALWARE' in out['threats']
    assert out['signals'][0]['level'] == 'bad'


def test_gather_signals_clean_link_not_dangerous(monkeypatch):
    monkeypatch.setattr(ur, 'google_safe_browsing', lambda url, timeout=5: {'status': 'success', 'threats': []})
    monkeypatch.setattr(ur, 'virustotal', lambda url, timeout=5: {'status': 'success', 'known': True, 'malicious': 0, 'suspicious': 0, 'harmless': 70})
    monkeypatch.setattr(ur, 'domain_age_signal', lambda d: None)
    assert ur.gather_signals('https://fine.example', 'fine.example', 'fine.example')['dangerous'] is False


def test_wikidata_official_domain_requires_close_name_match():
    search = {'search': [{'id': 'Q1', 'label': 'Foobank Limited', 'match': {'text': 'Foobank Limited'}},
                         {'id': 'Q2', 'label': 'Foobank', 'match': {'text': 'Foobank'}}]}
    entity = {'entities': {'Q2': {'claims': {'P856': [
        {'rank': 'normal', 'mainsnak': {'datavalue': {'value': 'https://www.foobank.in/'}}}]}}}}
    with mock.patch.object(ur.requests, 'get', side_effect=[_resp(search), _resp(entity)]):
        r = ur.wikidata_official_domains('Foobank')
    assert r['domains'] == ['foobank.in'] and r['entity'] == 'Foobank'
    with mock.patch.object(ur.requests, 'get', return_value=_resp({'search': [{'id': 'Q9', 'label': 'Something Else Entirely'}]})):
        assert ur.wikidata_official_domains('Foobank')['domains'] == []


# -------------------------------------------------------- image_provenance
def test_parse_manifest_detects_ai_and_edits_and_valid_signature():
    store = {'active_manifest': 'm1', 'validation_state': 'Valid', 'manifests': {'m1': {
        'claim_generator_info': [{'name': 'DALL-E', 'version': '3'}],
        'signature_info': {'issuer': 'OpenAI', 'time': '2025-01-01T00:00:00Z'},
        'assertions': [{'label': 'c2pa.actions.v2', 'data': {'actions': [
            {'action': 'c2pa.created', 'digitalSourceType': 'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia'},
            {'action': 'c2pa.edited'}]}}]}}}
    r = ip.parse_manifest_store(store)
    assert r['ai_generated'] is True and r['valid'] is True and r['issuer'] == 'OpenAI'
    assert 'c2pa.edited' in r['actions'] and r['claim_generator'] == 'DALL-E 3'


def test_parse_manifest_flags_broken_signature():
    store = {'active_manifest': 'm1', 'manifests': {'m1': {'claim_generator': 'Camera'}},
             'validation_status': [{'code': 'assertion.dataHash.mismatch'}]}
    r = ip.parse_manifest_store(store)
    assert r['valid'] is False and r['validation_failures'] == ['assertion.dataHash.mismatch']
    findings = ip.summarize({'c2pa': {**r, 'status': 'success'}})
    assert findings[0]['level'] == 'bad' and 'NO LONGER VALIDATES' in findings[0]['text']


def _jpeg():
    b = io.BytesIO()
    Image.new('RGB', (64, 64), (10, 120, 200)).save(b, 'JPEG')
    return b.getvalue()


def test_c2pa_absent_is_neutral_not_an_error():
    r = ip.check_c2pa(_jpeg(), 'plain.jpg')
    assert r['status'] in ('not_found', 'not_configured')


def test_reverse_search_and_detector_not_configured_without_keys(monkeypatch):
    for k in ('GOOGLE_VISION_API_KEY', 'SIGHTENGINE_API_USER', 'SIGHTENGINE_API_SECRET'):
        monkeypatch.delenv(k, raising=False)
    assert ip.reverse_image_search(b'x')['status'] == 'not_configured'
    assert ip.ai_detector(b'x')['status'] == 'not_configured'


def test_reverse_search_parses_matches(monkeypatch):
    monkeypatch.setenv('GOOGLE_VISION_API_KEY', 'k')
    body = {'responses': [{'webDetection': {
        'fullMatchingImages': [{'url': 'a'}], 'partialMatchingImages': [{'url': 'b'}],
        'pagesWithMatchingImages': [{'url': 'https://news.example/x', 'pageTitle': 'Old story'}],
        'bestGuessLabels': [{'label': 'flood photo'}]}}]}
    with mock.patch.object(ip.requests, 'post', return_value=_resp(body)):
        r = ip.reverse_image_search(b'x')
    assert r['exact_matches'] == 1 and r['pages'][0]['url'] == 'https://news.example/x'
    findings = ip.summarize({'reverse_search': r})
    assert findings[0]['level'] == 'warn'


def test_ai_detector_parses_probability(monkeypatch):
    monkeypatch.setenv('SIGHTENGINE_API_USER', 'u')
    monkeypatch.setenv('SIGHTENGINE_API_SECRET', 's')
    with mock.patch.object(ip.requests, 'post', return_value=_resp({'status': 'success', 'type': {'ai_generated': 0.97}})):
        r = ip.ai_detector(b'x', 'a.jpg')
    assert r['ai_probability'] == 0.97 and 'likely AI' in r['label']
    assert ip.summarize({'ai_detector': r})[0]['level'] == 'bad'


def test_ingest_marks_image_ai_generated_when_c2pa_declares_it(monkeypatch):
    from modules import evidence_ingest
    monkeypatch.setattr(ip, 'verify_image', lambda payload, filename='image': {
        'c2pa': {'status': 'success', 'valid': True, 'ai_generated': True, 'claim_generator': 'X', 'actions': []},
        'reverse_search': {'status': 'not_configured'}, 'ai_detector': {'status': 'not_configured'}})
    meta = evidence_ingest.extract_metadata(_jpeg(), 'image', 'a.jpg')
    assert meta['likely_ai_generated'] is True
    assert meta['provenance_findings']


# -------------------------------------------------------------- phone_intel
def test_offline_profile_indian_mobile_and_foreign_number():
    home = pi.offline_profile('+919876543210')
    assert home['valid'] is True and 'foreign' not in {s['name'] for s in home['signals']}
    foreign = pi.offline_profile('+14155550123')
    assert 'foreign' in {s['name'] for s in foreign['signals']}


def test_apply_to_score_is_modest():
    pts, reasons = pi.apply_to_score({'signals': [{'name': 'voip'}, {'name': 'foreign'}]}, {'signals': []})
    assert pts == 20 and len(reasons) == 2


def test_live_lookup_flags_voip(monkeypatch):
    monkeypatch.setenv('VERIPHONE_API_KEY', 'k')
    body = {'status': 'success', 'phone_valid': True, 'phone_type': 'voip', 'carrier': 'X'}
    with mock.patch.object(pi.requests, 'get', return_value=_resp(body)):
        r = pi.live_line_type('+14155550123')
    assert any(s['name'] == 'live_voip' for s in r['signals'])


def test_live_lookup_invalid_number_and_normal_mobile(monkeypatch):
    monkeypatch.setenv('VERIPHONE_API_KEY', 'k')
    with mock.patch.object(pi.requests, 'get', return_value=_resp({'status': 'success', 'phone_valid': False})):
        assert any(s['name'] == 'live_unknown' for s in pi.live_line_type('+919000000000')['signals'])
    with mock.patch.object(pi.requests, 'get', return_value=_resp({'status': 'success', 'phone_valid': True, 'phone_type': 'mobile', 'carrier': 'Jio'})):
        r = pi.live_line_type('+919876543210')
    assert r['signals'][0]['name'] == 'live_type' and 'Jio' in r['signals'][0]['text']


def test_live_lookup_not_configured_and_network_error(monkeypatch):
    monkeypatch.delenv('VERIPHONE_API_KEY', raising=False)
    assert pi.live_line_type('+919876543210')['status'] == 'not_configured'
    monkeypatch.setenv('VERIPHONE_API_KEY', 'k')
    with mock.patch.object(pi.requests, 'get', side_effect=pi.requests.exceptions.ConnectionError('down')):
        assert pi.live_line_type('+919876543210')['status'] == 'unavailable'


# -------------------------------------------------------------- scam_script
def test_script_with_otp_request_is_always_high():
    r = ss.analyze_call_script("Sir please just tell me the OTP you received, it is for verification.")
    assert r['severity'] == 'HIGH' and r['matches'][0]['category'] == 'secret_codes'


def test_digital_arrest_script_is_high_with_explanations():
    r = ss.analyze_call_script("This is CBI. You are under digital arrest, do not tell anyone, transfer the amount to the RBI safe account immediately.")
    cats = {m['category'] for m in r['matches']}
    assert {'authority_threat', 'secrecy', 'money_demand', 'urgency'} <= cats
    assert r['severity'] == 'HIGH' and all(m['why'] for m in r['matches'])


def test_hinglish_script_detected():
    assert ss.analyze_call_script("aapka SIM band ho jayega, abhi OTP batao")['severity'] == 'HIGH'


def test_ordinary_call_is_low_and_empty_is_handled():
    r = ss.analyze_call_script("Hi, it's Ravi from school. The parent meeting is moved to 5 pm tomorrow.")
    assert r['severity'] == 'LOW' and r['matches'] == []
    assert ss.analyze_call_script('   ')['status'] == 'empty'


# ----------------------------------------------------------------- routes
@pytest.fixture()
def _logged_in(client):
    client.post('/signup', data={'full_name': 'T A', 'email': 'acc@example.com', 'organization': '',
                                 'password': 'CorrectHorse1!', 'confirm_password': 'CorrectHorse1!'}, follow_redirects=True)
    return client


def test_check_number_route_uses_call_script(_logged_in, monkeypatch):
    from modules import web_corroboration
    monkeypatch.setattr(web_corroboration, 'check_web_corroboration', lambda *a, **k: {'status': 'not_configured'})
    r = _logged_in.post('/check-number', data={'number': '9876543210',
                        'transcript': 'I am from SBI, your KYC will be blocked, share the OTP now'})
    body = r.get_data(as_text=True)
    assert r.status_code == 200
    assert 'HIGH risk' in body and 'Asks for OTP / PIN / CVV / password' in body


def test_check_number_without_transcript_still_works(_logged_in, monkeypatch):
    from modules import web_corroboration
    monkeypatch.setattr(web_corroboration, 'check_web_corroboration', lambda *a, **k: {'status': 'not_configured'})
    r = _logged_in.post('/check-number', data={'number': '+919876543210'})
    assert r.status_code == 200 and 'About this number' in r.get_data(as_text=True)


def test_verify_site_route_renders_signals(_logged_in, monkeypatch):
    from modules import site_verification as sv
    monkeypatch.setattr(sv, '_host_exists', lambda h, timeout=2: None)
    monkeypatch.setattr(sv.url_reputation, 'gather_signals', lambda url, host, domain, skip_age=False: {
        'signals': [{'name': 'tld', 'level': 'warn', 'text': 'WARN-SIGNAL-TEXT'}], 'dangerous': False, 'threats': [], 'sources': {}})
    r = _logged_in.post('/verify-site', data={'brand': 'whatsapp', 'url': 'whatsapp-gold.xyz'})
    body = r.get_data(as_text=True)
    assert 'WARN-SIGNAL-TEXT' in body and 'NOT whatsapp' in body
