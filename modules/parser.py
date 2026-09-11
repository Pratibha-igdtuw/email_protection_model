"""
Module 1: Email upload + header/body parser
Parses raw email text (.eml or pasted) into a structured dict:
headers, body (plain+html), Received chain (hop by hop), extracted IPs.
"""
import re
import email
from email import policy
from email.parser import BytesParser, Parser

IP_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

PRIVATE_IP_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                        '172.2', '172.30.', '172.31.', '192.168.', '127.')


def _is_private_ip(ip):
    return ip.startswith(PRIVATE_IP_PREFIXES) or ip == '0.0.0.0'


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

    # Body extraction (plain preferred, fallback to html-stripped)
    body_plain = ""
    body_html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get('Content-Disposition') or '')
            if 'attachment' in disp:
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
        ips_found = IP_REGEX.findall(rec_str)
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
            m = IP_REGEX.search(str(xoi))
            if m:
                originating_ip = m.group(0)

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
        'originating_ip': originating_ip,
        'message_id': str(headers.get('Message-ID', '')) or None,
        'date': str(headers.get('Date', '')) or None,
    }


def extract_urls(text):
    if not text:
        return []
    url_regex = re.compile(r'https?://[^\s<>"\')]+')
    return list(set(url_regex.findall(text)))
