"""
Module 1 (AI layer): ML-based phishing classifier + NLP social-engineering
cue detection (urgency language, display-name/domain mismatch, suspicious
links, spoofed-domain lookalikes).
"""
import os
import re
import difflib
import joblib

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, '..', 'ml_model', 'phishing_model.joblib')

_model = None


def _get_model():
    global _model
    if _model is None and os.path.exists(MODEL_PATH):
        _model = joblib.load(MODEL_PATH)
    return _model


URGENCY_PHRASES = [
    'urgent', 'immediately', 'act now', 'verify your', 'suspended', 'final notice',
    'expire', 'expires', 'within 24 hours', 'within 48 hours', 'click here',
    'limited time', 'account will be', 'confirm your password', 'security alert',
    'unusual activity', 'claim your', 'locked', 'restricted', 'last warning',
    'immediate action', 'failure to respond',
]

WELL_KNOWN_DOMAINS = [
    'paypal.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'netflix.com', 'bankofamerica.com', 'chase.com', 'facebook.com', 'irs.gov',
    'icloud.com', 'outlook.com', 'linkedin.com', 'instagram.com', 'sbi.co.in',
    'hdfcbank.com', 'icicibank.com',
]

URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly', 'buff.ly', 'rebrand.ly']


def detect_urgency_language(text):
    if not text:
        return []
    text_lower = text.lower()
    return [p for p in URGENCY_PHRASES if p in text_lower]


def detect_display_name_mismatch(display_name, sender_domain):
    if not display_name or not sender_domain:
        return None
    dn_lower = display_name.lower()
    for brand_domain in WELL_KNOWN_DOMAINS:
        brand = brand_domain.split('.')[0]
        if brand in dn_lower and brand not in sender_domain.lower():
            return (f"Display name references '{brand.title()}' but sender domain is "
                    f"'{sender_domain}' — classic brand-impersonation mismatch.")
    return None


def detect_lookalike_domain(sender_domain):
    if not sender_domain:
        return None
    for legit in WELL_KNOWN_DOMAINS:
        if sender_domain == legit:
            continue
        ratio = difflib.SequenceMatcher(None, sender_domain, legit).ratio()
        if ratio > 0.75:
            return (f"'{sender_domain}' looks like a lookalike/typosquat of legitimate domain "
                    f"'{legit}' (similarity {ratio:.0%}).")
    return None


def detect_suspicious_links(urls):
    flags = []
    for u in urls:
        for shortener in URL_SHORTENERS:
            if shortener in u:
                flags.append(f"Shortened URL detected: {u} (masks true destination)")
                break
        else:
            m = re.search(r'https?://([^/]+)', u)
            if m:
                host = m.group(1)
                if re.match(r'^\d+\.\d+\.\d+\.\d+', host):
                    flags.append(f"Raw IP address used as link host: {u}")
    return flags


def classify_email(parsed_email, urls):
    """
    Returns:
      ml_probability: 0-100 phishing probability from the trained classifier
      red_flags: list of NLP/heuristic cue strings
      nlp_risk_score: 0-40 contribution to combined score (rule-based cues)
    """
    text = f"{parsed_email.get('subject', '')} {parsed_email.get('body_plain', '')}"

    model = _get_model()
    if model is not None and text.strip():
        try:
            proba = model.predict_proba([text])[0]
            classes = list(model.classes_)
            phishing_idx = classes.index(1) if 1 in classes else -1
            ml_probability = round(proba[phishing_idx] * 100, 1) if phishing_idx >= 0 else 0.0
        except Exception:
            ml_probability = 0.0
    else:
        ml_probability = 0.0

    urgency_hits = detect_urgency_language(text)
    dn_mismatch = detect_display_name_mismatch(parsed_email.get('display_name'), parsed_email.get('sender_domain'))
    lookalike = detect_lookalike_domain(parsed_email.get('sender_domain'))
    suspicious_links = detect_suspicious_links(urls)

    red_flags = []
    nlp_score = 0

    if urgency_hits:
        red_flags.append(f"Urgency/social-engineering language detected: {', '.join(urgency_hits[:5])}")
        nlp_score += min(3 + len(urgency_hits), 15)
    if dn_mismatch:
        red_flags.append(dn_mismatch)
        nlp_score += 12
    if lookalike:
        red_flags.append(lookalike)
        nlp_score += 15
    if suspicious_links:
        red_flags.extend(suspicious_links)
        nlp_score += min(5 * len(suspicious_links), 10)

    nlp_score = min(nlp_score, 40)

    return {
        'ml_probability': ml_probability,
        'red_flags': red_flags,
        'nlp_risk_score': nlp_score,
        'urgency_phrases_found': urgency_hits,
    }
