from modules import risk_score


def test_severity_bands():
    assert risk_score.severity_from_score(0) == 'Low'
    assert risk_score.severity_from_score(24) == 'Low'
    assert risk_score.severity_from_score(25) == 'Medium'
    assert risk_score.severity_from_score(50) == 'High'
    assert risk_score.severity_from_score(75) == 'Critical'
    assert risk_score.severity_from_score(100) == 'Critical'


def test_clean_email_scores_low():
    ml = {'ml_probability': 2, 'nlp_risk_score': 0}
    auth = {'auth_risk_score': 0}
    result = risk_score.compute_combined_score(ml, auth, {'mismatch_detected': False}, {}, 0)
    assert result['combined_score'] < 25
    assert result['severity'] == 'Low'


def test_high_risk_email_scores_critical():
    ml = {'ml_probability': 95, 'nlp_risk_score': 40}
    auth = {'auth_risk_score': 40}
    whois_result = {'is_newly_registered': True}
    geo_mismatch = {'mismatch_detected': True}
    result = risk_score.compute_combined_score(ml, auth, geo_mismatch, whois_result, 20)
    assert result['combined_score'] == 100
    assert result['severity'] == 'Critical'


def test_score_is_capped_at_100():
    ml = {'ml_probability': 100, 'nlp_risk_score': 100}
    auth = {'auth_risk_score': 100}
    result = risk_score.compute_combined_score(
        ml, auth, {'mismatch_detected': True}, {'is_newly_registered': True}, 20
    )
    assert result['combined_score'] <= 100


def test_breakdown_keys_present():
    ml = {'ml_probability': 50, 'nlp_risk_score': 10}
    auth = {'auth_risk_score': 10}
    result = risk_score.compute_combined_score(ml, auth, {'mismatch_detected': False}, {}, 0)
    expected_keys = {'content_ai_ml', 'content_nlp_cues', 'spf_dkim_dmarc_auth',
                      'blacklist_reputation', 'whois_domain_age', 'geo_anomaly',
                      'attachment_risk', 'url_risk'}
    assert set(result['breakdown'].keys()) == expected_keys


def test_attachment_and_url_risk_contribute_and_are_capped():
    ml = {'ml_probability': 0, 'nlp_risk_score': 0}
    auth = {'auth_risk_score': 0}
    # Both risk scores exceed their 15-pt cap -- the combined score should
    # only credit 15 pts each, not the raw (higher) values passed in.
    attachment_result = {'risk_score': 40}
    url_result = {'risk_score': 25}
    result = risk_score.compute_combined_score(
        ml, auth, {'mismatch_detected': False}, {}, 0,
        attachment_result=attachment_result, url_result=url_result,
    )
    assert result['breakdown']['attachment_risk'] == 15.0
    assert result['breakdown']['url_risk'] == 15.0
    assert result['combined_score'] == 30.0


def test_attachment_and_url_risk_default_to_zero_when_omitted():
    ml = {'ml_probability': 0, 'nlp_risk_score': 0}
    auth = {'auth_risk_score': 0}
    result = risk_score.compute_combined_score(ml, auth, {'mismatch_detected': False}, {}, 0)
    assert result['breakdown']['attachment_risk'] == 0.0
    assert result['breakdown']['url_risk'] == 0.0
