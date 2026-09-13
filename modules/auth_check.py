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
    """Extract spf=, dkim=, dmarc= results from an Authentication-Results
    (or ARC-Authentication-Results) header."""
    result = {'spf': None, 'dkim': None, 'dmarc': None}
    if not auth_results_header:
        return result
    text = str(auth_results_header)
    for key in ('spf', 'dkim', 'dmarc'):
        m = re.search(rf'{key}=(\w+)', text, re.IGNORECASE)
        if m:
            result[key] = m.group(1).lower()
    return result


def _merge_auth_results(primary, fallback):
    """Fill in any field primary left as None from fallback, without
    overwriting anything primary already found."""
    merged = dict(primary)
    for key in ('spf', 'dkim', 'dmarc'):
        if merged.get(key) is None:
            merged[key] = fallback.get(key)
    return merged


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


def _extract_domain_from_field(text, field_pattern):
    """Extract a domain from a pattern like 'smtp.mailfrom=user@domain.com'
    or 'header.i=@domain.com' within auth-results text."""
    if not text:
        return None
    m = re.search(field_pattern, text, re.IGNORECASE)
    if not m:
        return None
    value = m.group(1)
    return value.split('@')[-1].lower() if '@' in value else value.lower()


def _organizational_domain(hostname):
    """Rough registrable/organizational-domain approximation: last two
    labels, or three for common ccTLD-second-level patterns like .co.in /
    .ac.in. Good enough for DMARC alignment comparison -- not a full
    public-suffix-list implementation."""
    if not hostname:
        return hostname
    labels = hostname.lower().rstrip('.').split('.')
    if len(labels) >= 3 and labels[-2] in ('co', 'com', 'org', 'gov', 'ac', 'net', 'edu') and len(labels[-1]) == 2:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:]) if len(labels) >= 2 else hostname


def _compute_dmarc_alignment(auth_text, spf_result, dkim_result, sender_domain):
    """Used only when no header explicitly states dmarc= (common -- not
    every relay stamps it). Computes real DMARC alignment ourselves: DMARC
    passes if EITHER SPF or DKIM both (a) passed and (b) is "aligned" --
    its checked domain shares an organizational domain with the From:
    header's domain. This catches a very common real-world case: Google
    Workspace signs with its own default <tenant>.gappssmtp.com DKIM
    domain when the organization hasn't configured custom DKIM, which
    passes DKIM cryptographically but does NOT align with the
    organization's actual domain -- so DMARC correctly fails even though
    every individual field looks fine on its own."""
    if not sender_domain or not auth_text:
        return None
    from_org_domain = _organizational_domain(sender_domain)

    spf_aligned = False
    if spf_result == 'pass':
        mailfrom_domain = _extract_domain_from_field(auth_text, r'smtp\.mailfrom=([^\s;]+)')
        if mailfrom_domain:
            spf_aligned = _organizational_domain(mailfrom_domain) == from_org_domain

    dkim_aligned = False
    if dkim_result == 'pass':
        dkim_domain = _extract_domain_from_field(auth_text, r'header\.[id]=([^\s;]+)')
        if dkim_domain:
            dkim_aligned = _organizational_domain(dkim_domain) == from_org_domain

    return 'pass' if (spf_aligned or dkim_aligned) else 'fail'


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

    arc_auth_results_raw = headers.get('ARC-Authentication-Results')
    if isinstance(arc_auth_results_raw, list):
        arc_auth_results_raw = ' '.join(str(a) for a in arc_auth_results_raw)

    parsed_auth = _merge_auth_results(
        _parse_auth_results(auth_results_raw),
        _parse_auth_results(arc_auth_results_raw),
    )

    received_spf = headers.get('Received-SPF')
    spf_from_received = _parse_received_spf(received_spf)

    dkim_sig_present = bool(headers.get('DKIM-Signature'))

    spf_result = parsed_auth['spf'] or spf_from_received or 'none'
    dkim_result = parsed_auth['dkim'] or ('none' if not dkim_sig_present else 'present_unverified')

    combined_auth_text = ' '.join(filter(None, [auth_results_raw, arc_auth_results_raw]))
    dmarc_result = parsed_auth['dmarc'] \
        or _compute_dmarc_alignment(combined_auth_text, spf_result, dkim_result, sender_domain) \
        or 'none'

    dmarc_dns = check_dmarc_dns(sender_domain)
    published_policy = (dmarc_dns['policy'] if dmarc_dns else None) \
        or _parse_policy_from_auth_results(auth_results_raw) \
        or _parse_policy_from_auth_results(arc_auth_results_raw)

    # --- Weighted verdict ---
    # Auth failure is treated as a HIGH-weight signal, distinct from soft NLP cues.
    high_weight_flags = []
    score = 0  # contribution to combined risk score (0-40 band reserved for auth)

    if spf_result in ('fail', 'softfail', 'none'):
        if spf_result == 'none':
            high_weight_flags.append("SPF NONE: domain publishes no SPF record at all")
        else:
            high_weight_flags.append(f"SPF {spf_result.upper()}: sending IP not authorized by domain's SPF record")
        score += 15 if spf_result == 'fail' else (8 if spf_result == 'softfail' else 6)
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
        'raw_arc_authentication_results': arc_auth_results_raw,
        'raw_received_spf': str(received_spf) if received_spf else None,
        'high_weight_flags': high_weight_flags,
        'auth_risk_score': score,  # out of 40, feeds into combined risk score
    }