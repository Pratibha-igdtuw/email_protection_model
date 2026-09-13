"""
Module 4 core logic: Unified Dashboard combined risk score.
Merges content AI (ML+NLP), geo anomaly, SPF/DKIM/DMARC authentication,
WHOIS domain age, blacklist/reputation, and attachment risk into ONE
0-100 risk score with a severity tag (Low/Medium/High/Critical).
"""

SEVERITY_BANDS = [
    (75, 100, 'Critical'),
    (50, 74, 'High'),
    (25, 49, 'Medium'),
    (0, 24, 'Low'),
]


def severity_from_score(score):
    for low, high, label in SEVERITY_BANDS:
        if low <= score <= high:
            return label
    return 'Low'


def compute_combined_score(ml_result, auth_result, geo_mismatch, whois_result, blacklist_score,
                            attachment_result=None, url_result=None):
    """
    Weighting rationale:
      - ML content probability: up to 30 pts   (weight 0.30)
      - NLP/heuristic red flags: up to 20 pts  (weight 0.50 of its 40-pt scale)
      - SPF/DKIM/DMARC auth:     up to 30 pts  (weight 0.75 of its 40-pt scale)
                                  -> treated as high-weight per spec, strongest signal
      - Blacklist/reputation:    up to 20 pts  (weight 1.0 of its 20-pt scale)
      - WHOIS newly-registered domain: flat +10 pts
      - GeoIP brand/hosting mismatch:  flat +10 pts
      - Attachment risk (dangerous/double-extension/macro files): up to 15 pts
      - URL risk (IP-literal, shortener, punycode, brand impersonation,
        anchor text/href mismatch): up to 15 pts
    Capped at 100. attachment_result/url_result are optional/backward-compatible
    -- callers that don't pass them simply get zero contribution from that category.
    """
    ml_contribution = round((ml_result.get('ml_probability', 0) / 100) * 30, 1)
    nlp_contribution = round((ml_result.get('nlp_risk_score', 0) / 40) * 20, 1)
    auth_contribution = round((auth_result.get('auth_risk_score', 0) / 40) * 30, 1)
    blacklist_contribution = round((blacklist_score / 20) * 20, 1) if blacklist_score else 0.0

    whois_flagged = whois_result and (
        whois_result.get('is_newly_registered') or whois_result.get('status') == 'not_registered'
    )
    whois_contribution = 10.0 if whois_flagged else 0.0
    geo_contribution = 10.0 if (geo_mismatch and geo_mismatch.get('mismatch_detected')) else 0.0
    attachment_contribution = round(min(attachment_result.get('risk_score', 0), 15), 1) if attachment_result else 0.0
    url_contribution = round(min(url_result.get('risk_score', 0), 15), 1) if url_result else 0.0

    total = ml_contribution + nlp_contribution + auth_contribution + blacklist_contribution \
        + whois_contribution + geo_contribution + attachment_contribution + url_contribution
    total = round(min(total, 100), 1)

    breakdown = {
        'content_ai_ml': ml_contribution,
        'content_nlp_cues': nlp_contribution,
        'spf_dkim_dmarc_auth': auth_contribution,
        'blacklist_reputation': blacklist_contribution,
        'whois_domain_age': whois_contribution,
        'geo_anomaly': geo_contribution,
        'attachment_risk': attachment_contribution,
        'url_risk': url_contribution,
    }

    return {
        'combined_score': total,
        'severity': severity_from_score(total),
        'breakdown': breakdown,
    }