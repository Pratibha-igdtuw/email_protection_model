"""
Module 1: Email upload + header/body parser
Parses raw email text (.eml or pasted) into a structured dict:
headers, body (plain+html), Received chain (hop by hop), extracted IPs.
"""
import re
import ipaddress
import hashlib
import email
from email import policy
from email.parser import BytesParser, Parser

# Loose candidate patterns -- deliberately permissive. Anything that merely
# *looks* IPv4/IPv6-shaped gets found here; actual validity (including
# rejecting ambiguous things like leading-zero octets, which Python's
# ipaddress module correctly treats as invalid per CVE-2021-29921) is
# decided by _extract_valid_ips below, not by the regex.
IPV4_CANDIDATE_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
IPV6_CANDIDATE_REGEX = re.compile(r'\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b')


def _extract_valid_ips(text):
    """Find IPv4/IPv6-shaped substrings in text and keep only the ones that
    are genuinely valid IP addresses. Real mail (especially anything
    relayed through Google/Microsoft infrastructure) very commonly carries
    IPv6 originating addresses -- a v4-only regex silently misses those
    entirely, and a bare regex with no validation can also accept spurious
    matches (digit sequences that happen to look dotted-decimal but aren't
    really an IP) as if they were real."""
    candidates = IPV4_CANDIDATE_REGEX.findall(text) + IPV6_CANDIDATE_REGEX.findall(text)
    valid, seen = [], set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            ipaddress.ip_address(candidate)
            valid.append(candidate)
        except ValueError:
            continue  # looked IP-shaped but wasn't a real, unambiguous address
    return valid


def _is_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local \
            or addr.is_reserved or addr.is_unspecified
    except ValueError:
        return True  # not even a valid address -- never treat as a usable public IP


def parse_email(raw_bytes_or_str):
    """Parse raw email content (bytes or str) into structured dict."""
    if isinstance(raw_bytes_or_str, str):
        raw_bytes = raw_bytes_or_str.encode('utf-8', errors='replace')
    else:
        raw_bytes = raw_bytes_or_str

    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    headers = {}
    for key in msg.keys():
        vals = msg.get_all(key)
        headers[key] = vals if len(vals) > 1 else vals[0]

    # Body extraction (plain preferred, fallback to html-stripped).
    # Attachments were previously silently discarded here -- now extracted
    # with metadata (filename/type/size/hash) for attachment_scan.py to
    # flag dangerous file types, double extensions, etc.
    body_plain = ""
    body_html = ""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            disp = str(part.get('Content-Disposition') or '')
            filename = part.get_filename()

            # A filename being present is a more reliable attachment signal
            # than the Content-Disposition string alone -- some phishing
            # emails mark a file 'inline' specifically to dodge naive
            # "if 'attachment' in disposition" checks.
            if filename or 'attachment' in disp.lower():
                try:
                    payload = part.get_payload(decode=True) or b''
                except Exception:
                    payload = b''
                attachments.append({
                    'filename': filename or '(unnamed)',
                    'content_type': ctype,
                    'size_bytes': len(payload),
                    'sha256': hashlib.sha256(payload).hexdigest() if payload else None,
                })
                continue

            try:
                if ctype == 'text/plain' and not body_plain:
                    body_plain = part.get_content()
                elif ctype == 'text/html' and not body_html:
                    body_html = part.get_content()
            except Exception:
                continue
    else:
        try:
            if msg.get_content_type() == 'text/html':
                body_html = msg.get_content()
            else:
                body_plain = msg.get_content()
        except Exception:
            body_plain = str(msg.get_payload())

    if not body_plain and body_html:
        body_plain = re.sub('<[^<]+?>', ' ', body_html)
        body_plain = re.sub(r'\s+', ' ', body_plain).strip()

    # Received header chain, in order received (top = most recent hop)
    received_headers = msg.get_all('Received') or []
    hops = []
    for idx, rec in enumerate(received_headers):
        rec_str = str(rec)
        ips_found = _extract_valid_ips(rec_str)
        public_ips = [ip for ip in ips_found if not _is_private_ip(ip)]
        ts_match = re.search(r';\s*(.+)$', rec_str)
        timestamp = ts_match.group(1).strip() if ts_match else None
        from_match = re.search(r'from\s+(\S+)', rec_str)
        by_match = re.search(r'by\s+(\S+)', rec_str)
        hops.append({
            'hop_number': idx + 1,
            'raw': rec_str,
            'from_host': from_match.group(1) if from_match else None,
            'by_host': by_match.group(1) if by_match else None,
            'ips': ips_found,
            'public_ips': public_ips,
            'timestamp': timestamp,
        })

    # Originating IP heuristic: last Received header (bottom of chain,
    # closest to sender) that carries a public IP
    originating_ip = None
    for hop in reversed(hops):
        if hop['public_ips']:
            originating_ip = hop['public_ips'][0]
            break
    if not originating_ip:
        # fallback: scan X-Originating-IP or any public IP anywhere in headers
        xoi = headers.get('X-Originating-IP')
        if xoi:
            found = _extract_valid_ips(str(xoi))
            if found:
                originating_ip = found[0]

    from_header = str(headers.get('From', ''))
    display_name_match = re.match(r'^\s*"?([^"<]*)"?\s*<', from_header)
    display_name = display_name_match.group(1).strip() if display_name_match else None
    domain_match = re.search(r'@([\w.-]+)', from_header)
    sender_domain = domain_match.group(1).lower() if domain_match else None

    return {
        'headers': headers,
        'subject': str(headers.get('Subject', '')),
        'from_raw': from_header,
        'display_name': display_name,
        'sender_domain': sender_domain,
        'reply_to': str(headers.get('Reply-To', '')) or None,
        'return_path': str(headers.get('Return-Path', '')) or None,
        'body_plain': body_plain,
        'body_html': body_html,
        'received_chain': hops,
        'attachments': attachments,
        'originating_ip': originating_ip,
        'message_id': str(headers.get('Message-ID', '')) or None,
        'date': str(headers.get('Date', '')) or None,
    }


def extract_urls(text):
    if not text:
        return []
    url_regex = re.compile(r'https?://[^\s<>"\')]+')
    return list(set(url_regex.findall(text)))