"""
Module 3: Email Authentication Check - SPF, DKIM, DMARC
Primary strategy: parse Authentication-Results / Received-SPF / DKIM-Signature
headers (fast, works offline, matches what most parsers/MTAs already verified).
Fallback: attempt a live DMARC TXT DNS lookup via dnspython if available and
network access is permitted (safe no-op on failure).
"""
import re

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def _parse_auth_results(auth_results_header):
    """Extract spf=, dkim=, dmarc= results from an Authentication-Results header."""
    result = {'spf': None, 'dkim': None, 'dmarc': None}
    if not auth_results_header:
        return result
    text = str(auth_results_header)
    for key in ('spf', 'dkim', 'dmarc'):
        m = re.search(rf'{key}=(\w+)', text, re.IGNORECASE)
        if m:
            result[key] = m.group(1).lower()
    return result


def _parse_policy_from_auth_results(auth_results_header):
    """Some MTAs already annotate the published DMARC policy inline, e.g.
    'dmarc=fail (p=reject) header.from=...'. Use this as a fallback when a
    live DNS lookup isn't possible (offline dev environment, blocked egress)."""
    if not auth_results_header:
        return None
    text = str(auth_results_header)
    m = re.search(r'\(p=(\w+)\)', text) or re.search(r'\bpolicy=(\w+)', text, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _parse_received_spf(received_spf_header):
    if not received_spf_header:
        return None
    text = str(received_spf_header).strip()
    m = re.match(r'^(\w+)', text)
    return m.group(1).lower() if m else None


def check_dmarc_dns(domain):
    """Best-effort live DMARC policy lookup. Returns dict or None on failure."""
    if not DNS_AVAILABLE or not domain:
        return None
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=3)
        for rdata in answers:
            txt = b''.join(rdata.strings).decode('utf-8', errors='replace')
            if 'v=DMARC1' in txt:
                policy_match = re.search(r'p=(\w+)', txt)
                pct_match = re.search(r'pct=(\d+)', txt)
                return {
                    'record': txt,
                    'policy': policy_match.group(1) if policy_match else 'none',
                    'pct': pct_match.group(1) if pct_match else '100',
                }
    except Exception:
        return None
    return None


def run_authentication_check(parsed_email):
    """
    Combines header-based results (primary) with an optional live DMARC
    DNS lookup (secondary, used to confirm the published policy).
    Returns a structured result + a weighted red-flag verdict.
    """
    headers = parsed_email.get('headers', {})
    sender_domain = parsed_email.get('sender_domain')

    auth_results_raw = headers.get('Authentication-Results')
    if isinstance(auth_results_raw, list):
        auth_results_raw = ' '.join(str(a) for a in auth_results_raw)

    parsed_auth = _parse_auth_results(auth_results_raw)

    received_spf = headers.get('Received-SPF')
    spf_from_received = _parse_received_spf(received_spf)

    dkim_sig_present = bool(headers.get('DKIM-Signature'))

    spf_result = parsed_auth['spf'] or spf_from_received or ('none' if not dkim_sig_present else None) or 'none'
    dkim_result = parsed_auth['dkim'] or ('none' if not dkim_sig_present else 'present_unverified')
    dmarc_result = parsed_auth['dmarc'] or 'none'

    dmarc_dns = check_dmarc_dns(sender_domain)
    published_policy = (dmarc_dns['policy'] if dmarc_dns else None) \
        or _parse_policy_from_auth_results(auth_results_raw)

    # --- Weighted verdict ---
    # Auth failure is treated as a HIGH-weight signal, distinct from soft NLP cues.
    high_weight_flags = []
    score = 0  # contribution to combined risk score (0-40 band reserved for auth)

    if spf_result in ('fail', 'softfail'):
        high_weight_flags.append(f"SPF {spf_result.upper()}: sending IP not authorized by domain's SPF record")
        score += 15 if spf_result == 'fail' else 8
    if dkim_result in ('fail', 'none'):
        high_weight_flags.append(f"DKIM {dkim_result.upper()}: message signature missing or invalid")
        score += 12 if dkim_result == 'fail' else 6
    if dmarc_result in ('fail', 'none'):
        weight = 15 if dmarc_result == 'fail' else 5
        note = f"DMARC {dmarc_result.upper()}"
        if published_policy in ('reject', 'quarantine'):
            note += f" combined with published policy p={published_policy} — strong spoofing indicator"
            weight += 10
        high_weight_flags.append(note)
        score += weight

    score = min(score, 40)

    return {
        'spf': spf_result,
        'dkim': dkim_result,
        'dmarc': dmarc_result,
        'dmarc_published_policy': published_policy,
        'dmarc_dns_lookup_attempted': DNS_AVAILABLE,
        'dmarc_dns_record': dmarc_dns['record'] if dmarc_dns else None,
        'raw_authentication_results': auth_results_raw,
        'raw_received_spf': str(received_spf) if received_spf else None,
        'high_weight_flags': high_weight_flags,
        'auth_risk_score': score,  # out of 40, feeds into combined risk score
    }
