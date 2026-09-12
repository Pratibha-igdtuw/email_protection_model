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


def reload_model():
    """Force a re-read of the model file from disk — called after the
    self-improving feedback loop retrains and overwrites the .joblib file,
    so newly analyzed emails immediately use the updated classifier."""
    global _model
    _model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None
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


_EXPLANATION_NOISE_TOKENS = {'https', 'http', 'www', 'com', 'net', 'org', 'html', 'php'}


def _is_noise_token(token):
    """True if every word in this token (which may be a 1- or 2-gram) is a
    URL-scheme/TLD fragment or a bare number. These are real features the
    model uses and stay in ml_probability -- this only keeps them out of
    the human-readable explanation, where 'https'/'net'/'24' read as
    confusing noise rather than an interpretable reason."""
    for part in token.split():
        if not (part.isdigit() or part in _EXPLANATION_NOISE_TOKENS):
            return False
    return True


def explain_classification(text, top_n=6):
    """
    Returns which tokens actually present in this email pushed the model's
    decision toward phishing vs. legitimate, and by how much.

    For MultinomialNB, log P(class|doc) is (up to a constant) a weighted sum
    over features of tfidf_weight * feature_log_prob_[class]. So the
    per-token contribution to the phishing-vs-legit log-odds is
    tfidf_weight * (feature_log_prob_[phishing] - feature_log_prob_[legit]).
    Summing these approximately reconstructs why predict_proba came out the
    way it did, token by token -- which is the piece a bare probability
    number doesn't give an analyst.
    """
    model = _get_model()
    if model is None or not text or not text.strip():
        return {'toward_phishing': [], 'toward_legitimate': []}
    try:
        tfidf = model.named_steps['tfidf']
        clf = model.named_steps['clf']
        classes = list(clf.classes_)
        if 1 not in classes or 0 not in classes:
            return {'toward_phishing': [], 'toward_legitimate': []}
        phishing_idx = classes.index(1)
        legit_idx = classes.index(0)

        X = tfidf.transform([text])
        feature_names = tfidf.get_feature_names_out()
        log_odds = clf.feature_log_prob_[phishing_idx] - clf.feature_log_prob_[legit_idx]

        contributions = []
        coo = X.tocoo()
        for col, weight in zip(coo.col, coo.data):
            token = feature_names[col]
            if _is_noise_token(token):
                continue
            contributions.append({
                'token': token,
                'contribution': float(weight) * float(log_odds[col]),
            })

        toward_phishing = sorted([c for c in contributions if c['contribution'] > 0],
                                  key=lambda c: c['contribution'], reverse=True)[:top_n]
        toward_legit = sorted([c for c in contributions if c['contribution'] < 0],
                               key=lambda c: c['contribution'])[:top_n]

        return {'toward_phishing': toward_phishing, 'toward_legitimate': toward_legit}
    except Exception:
        # Explanation is a nice-to-have on top of the probability, never a
        # requirement -- any unexpected model/vectorizer shape degrades to
        # "no explanation available" rather than breaking the analysis.
        return {'toward_phishing': [], 'toward_legitimate': []}


def explain_saved_case(case):
    """
    Reconstructs the same 'why was this flagged' explanation shown right
    after analysis (ml_explanation + red_flags), but from a Case row that
    was saved earlier -- for the case-detail page, which previously showed
    a bare score with no way to see why.

    Nothing extra is stored on the Case for this: body_text is already
    persisted (for feedback-loop retraining), the classifier is
    deterministic, and sender_from/sender_domain are already columns --
    so the explanation is recomputed on read rather than duplicating data.
    Degrades to empty lists (not an error) if body_text is missing, e.g.
    for older cases saved before body_text was added.
    """
    text = case.body_text or ''
    ml_explanation = explain_classification(text)

    display_name = None
    if case.sender_from:
        m = re.match(r'^\s*"?([^"<]*)"?\s*<', case.sender_from)
        if m:
            display_name = m.group(1).strip() or None

    urls = []
    try:
        from modules.parser import extract_urls
        urls = extract_urls(text)
    except Exception:
        pass

    red_flags = []
    urgency_hits = detect_urgency_language(text)
    dn_mismatch = detect_display_name_mismatch(display_name, case.sender_domain)
    lookalike = detect_lookalike_domain(case.sender_domain)
    suspicious_links = detect_suspicious_links(urls)

    if urgency_hits:
        red_flags.append(f"Urgency/social-engineering language detected: {', '.join(urgency_hits[:5])}")
    if dn_mismatch:
        red_flags.append(dn_mismatch)
    if lookalike:
        red_flags.append(lookalike)
    if suspicious_links:
        red_flags.extend(suspicious_links)

    return {'ml_explanation': ml_explanation, 'red_flags': red_flags}


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

    ml_explanation = explain_classification(text)

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
        'ml_explanation': ml_explanation,
        'red_flags': red_flags,
        'nlp_risk_score': nlp_score,
        'urgency_phrases_found': urgency_hits,
    }