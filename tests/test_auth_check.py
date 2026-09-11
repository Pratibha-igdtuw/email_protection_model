from modules import auth_check


def _parsed(headers):
    return {'headers': headers, 'sender_domain': 'example.com'}


def test_all_pass_scores_zero(monkeypatch):
    monkeypatch.setattr(auth_check, 'check_dmarc_dns', lambda domain: None)
    parsed = _parsed({
        'Authentication-Results': 'mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass; dmarc=pass',
        'DKIM-Signature': 'v=1; a=rsa-sha256;',
    })
    result = auth_check.run_authentication_check(parsed)
    assert result['spf'] == 'pass'
    assert result['dkim'] == 'pass'
    assert result['dmarc'] == 'pass'
    assert result['auth_risk_score'] == 0
    assert result['high_weight_flags'] == []


def test_spf_dkim_dmarc_fail_scores_high(monkeypatch):
    monkeypatch.setattr(auth_check, 'check_dmarc_dns', lambda domain: None)
    parsed = _parsed({
        'Authentication-Results': ('mx.example.com; spf=fail smtp.mailfrom=evil.com; '
                                    'dkim=fail; dmarc=fail (p=reject) header.from=evil.com'),
    })
    result = auth_check.run_authentication_check(parsed)
    assert result['spf'] == 'fail'
    assert result['dkim'] == 'fail'
    assert result['dmarc'] == 'fail'
    assert result['dmarc_published_policy'] == 'reject'
    assert result['auth_risk_score'] == 40  # capped at the 40-point band
    assert len(result['high_weight_flags']) == 3


def test_missing_headers_defaults_to_none(monkeypatch):
    monkeypatch.setattr(auth_check, 'check_dmarc_dns', lambda domain: None)
    parsed = _parsed({})
    result = auth_check.run_authentication_check(parsed)
    assert result['spf'] == 'none'
    assert result['dkim'] == 'none'
    assert result['dmarc'] == 'none'
    assert result['auth_risk_score'] > 0


def test_received_spf_header_fallback(monkeypatch):
    monkeypatch.setattr(auth_check, 'check_dmarc_dns', lambda domain: None)
    parsed = _parsed({'Received-SPF': 'softfail (domain owner discourages use of this host)'})
    result = auth_check.run_authentication_check(parsed)
    assert result['spf'] == 'softfail'
