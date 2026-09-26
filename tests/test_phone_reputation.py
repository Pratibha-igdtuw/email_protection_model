from modules import phone_reputation


def test_normalize_number_empty():
    normalized, display, error = phone_reputation.normalize_number('')
    assert normalized is None
    assert error


def test_normalize_number_too_short():
    normalized, display, error = phone_reputation.normalize_number('123')
    assert normalized is None
    assert error


def test_normalize_number_valid_fallback(monkeypatch):
    # Force the regex-fallback path regardless of whether `phonenumbers` is
    # installed in this environment, so the test is deterministic.
    monkeypatch.setattr(phone_reputation, '_HAS_PHONENUMBERS', False)
    normalized, display, error = phone_reputation.normalize_number('+1 (800) 555-0172')
    assert error is None
    assert normalized == '18005550172'


def test_check_scam_number_list_hit(monkeypatch):
    monkeypatch.setattr(phone_reputation, '_scam_numbers', {
        '18005550172': {'category': 'IRS impersonation scam', 'report_count': '10', 'last_reported': '2026-01-01'}
    })
    monkeypatch.setattr(phone_reputation, '_load_scam_numbers', lambda: phone_reputation._scam_numbers)

    result = phone_reputation.check_scam_number_list('18005550172')
    assert result['status'] == 'checked'
    assert result['hit']['category'] == 'IRS impersonation scam'


def test_check_scam_number_list_no_hit(monkeypatch):
    monkeypatch.setattr(phone_reputation, '_scam_numbers', {
        '18005550172': {'category': 'IRS impersonation scam', 'report_count': '10', 'last_reported': '2026-01-01'}
    })
    monkeypatch.setattr(phone_reputation, '_load_scam_numbers', lambda: phone_reputation._scam_numbers)

    result = phone_reputation.check_scam_number_list('19995551234')
    assert result['hit'] is None


def test_check_ipqualityscore_not_configured(monkeypatch):
    monkeypatch.delenv('IPQUALITYSCORE_API_KEY', raising=False)
    result = phone_reputation.check_ipqualityscore('18005550172')
    assert result['status'] == 'not_configured'


def test_compute_phone_score_no_hits():
    score, severity, reasons = phone_reputation.compute_phone_score(
        [], {'hit': None}, {'status': 'not_configured'})
    assert score == 0
    assert severity == 'LOW'
    assert reasons  # explains the absence-of-match caveat


def test_compute_phone_score_local_hit():
    local_hits = [{'indicator': '+18005550172', 'reason': 'reported by a user', 'added_on': '2026-01-01'}]
    score, severity, reasons = phone_reputation.compute_phone_score(
        local_hits, {'hit': None}, {'status': 'not_configured'})
    assert score >= 40
    assert any('own reported-number list' in r for r in reasons)


def test_compute_phone_score_community_hit_is_medium_or_high():
    scam_hit = {'hit': {'category': 'Bank impersonation scam', 'report_count': '50', 'last_reported': '2026-01-01'}}
    score, severity, reasons = phone_reputation.compute_phone_score([], scam_hit, {'status': 'not_configured'})
    assert score >= 30
    assert severity in ('MEDIUM', 'HIGH')
    assert any('Bank impersonation scam' in r for r in reasons)


def test_compute_phone_score_api_recent_abuse_pushes_high():
    local_hits = [{'indicator': '+18005550172', 'reason': 'x', 'added_on': '2026-01-01'}]
    scam_hit = {'hit': {'category': 'Robocall', 'report_count': '5', 'last_reported': '2026-01-01'}}
    api_result = {'status': 'success', 'fraud_score': 90, 'recent_abuse': True, 'line_type': 'Voip'}
    score, severity, reasons = phone_reputation.compute_phone_score(local_hits, scam_hit, api_result)
    assert score == 100
    assert severity == 'HIGH'