"""
Module: Trusted Relay Reconstruction ("Earliest Reliable Hop" identification)

Builds on top of modules/parser.py's already-extracted Received header
chain -- no re-parsing, no schema changes, just a second pass over
`parsed_email['received_chain']`.

--- The forensic idea ---
Received headers are prepended by every MTA a message passes through, so
the chain read top-to-bottom is most-recent-hop-first. Each hop line has
two host claims:
  - `by`   -- the server that generated *this* header line. That server
             controls its own logging, so this claim is only as
             trustworthy as the operator of that server.
  - `from` -- the host that connected to it, as reported by the
             connecting client. This is self-reported and trivially
             forgeable by anyone who controls that client.

An attacker forging a phishing trail can prepend as many fake
"Received: from spoofed.node by spoofed.relay" lines as they like into
the header block *before* the message ever touched real mail
infrastructure. Those fake lines are indistinguishable from real ones by
looking at any single header alone.

What CAN'T be forged (without compromising that provider's own MTA) is
the header stamped by a receiving server we actually trust -- our own
mail infrastructure, or a major mailbox/relay provider with server-side
logging. Walking DOWN the chain (from most recent hop toward the
original sender) and stopping at the first hop whose `by` field is one
of those verified servers gives us a "trust boundary": the `from` value
recorded on *that specific hop* is a first-hand, server-observed fact.
Everything past that boundary (i.e. earlier hops, further from the
recipient) is self-reported chain content that could have been
fabricated before ever reaching a server we trust, so it is marked
Untrusted rather than taken at face value.

This module does not change how the chain is parsed; it only classifies
hops that are already available and geolocates each hop's IP (reusing
modules/geoip.py) to surface a defensible "Earliest Reliable Sending
Node" with a transparent, explainable confidence score.
"""
import concurrent.futures
import ipaddress
import re

from modules import geoip as geoip_mod

# Operators of major inbound mail infrastructure. A 'by' host matching one
# of these is treated as a verified receiving server: forging the
# "Received: by ..." stamp itself would require compromising the
# provider's own MTA, not just crafting an email.
TRUSTED_RELAY_DOMAINS = [
    'google.com', 'googlemail.com', 'gmail.com', 'gmr-mx.google.com',
    'outlook.com', 'protection.outlook.com', 'outbound.protection.outlook.com',
    'exchangelabs.com', 'office365.com',
    'yahoo.com', 'yahoodns.net', 'yahoo-inc.com',
    'mail.ru',
    'zoho.com', 'zohomail.com',
    'amazonses.com', 'ses.amazonaws.com',
    'messagingengine.com', 'fastmail.com',
    'pphosted.com',        # Proofpoint
    'mimecast.com',
    'barracudanetworks.com',
    'sendgrid.net',
    'mailgun.org',
    'icloud.com', 'apple.com',
]


def _clean_host(host):
    if not host:
        return ''
    return host.lower().strip().strip('[]').rstrip('.')


def _host_is_trusted_relay(host, recipient_domain=None):
    host_l = _clean_host(host)
    if not host_l:
        return False
    if recipient_domain and _clean_host(recipient_domain) in host_l:
        return True
    return any(td in host_l for td in TRUSTED_RELAY_DOMAINS)


def extract_recipient_domain(headers):
    """Best-effort domain of the actual recipient mailbox, used to also
    recognize an organization's own mail infrastructure as trusted (not
    just the big public providers). Checked in order of reliability:
    a receiving MTA writes Delivered-To/X-Original-To itself, whereas
    'To' is just a message header and easier to spoof, so it's the
    weakest signal here and used only as a last resort."""
    for key in ('Delivered-To', 'X-Original-To', 'Envelope-To', 'To'):
        val = headers.get(key)
        if not val:
            continue
        val = val[0] if isinstance(val, list) else val
        match = re.search(r'@([\w.-]+)', str(val))
        if match:
            return match.group(1).lower()
    return None


def _classify_hop(by_trusted, by_host, past_boundary):
    if past_boundary:
        return 'Untrusted', [
            "This hop appears before the first verified receiving server in the chain -- "
            "its 'from'/'by' values are self-reported by an unverified host and could have "
            "been inserted or forged prior to reaching real mail infrastructure."
        ]
    if by_trusted:
        return 'Trusted', [f"Receiving server '{by_host}' matches recognized mail infrastructure."]
    return 'Suspicious', ["Receiving server identity could not be matched against known/organizational infrastructure."]


def reconstruct_trusted_relay(parsed_email, recipient_domain=None):
    """
    parsed_email: dict from modules.parser.parse_email (uses 'received_chain'
    and 'headers'; does not mutate either).
    recipient_domain: optional override; if not supplied it's derived from
    the message's own headers via extract_recipient_domain().

    Returns:
    {
      'trust_boundary_hop_number': int or None,
      'hops': [ { hop_number, status ('Trusted'/'Suspicious'/'Untrusted'),
                  reasons, from_host, by_host, ip, all_ips, country, asn,
                  isp, is_hosting_provider, timestamp,
                  consistent_with_next_hop }, ... ],
      'earliest_reliable_node': {
          ip, from_host, verified_by, country, asn, isp, confidence,
          summary, unverified (bool)
      } or None,
    }
    """
    hops = parsed_email.get('received_chain') or []
    if not hops:
        return {'trust_boundary_hop_number': None, 'hops': [], 'earliest_reliable_node': None}

    if recipient_domain is None:
        recipient_domain = extract_recipient_domain(parsed_email.get('headers', {}) or {})

    # Geolocate every distinct public IP across the whole chain up front
    # (one HTTP call per unique IP, run concurrently) rather than one call
    # per hop sequentially.
    unique_ips = sorted({ip for hop in hops for ip in (hop.get('public_ips') or [])})
    geo_by_ip = {}
    if unique_ips:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(unique_ips))) as pool:
            futures = {pool.submit(geoip_mod.lookup_ip, ip): ip for ip in unique_ips}
            for fut in concurrent.futures.as_completed(futures):
                ip = futures[fut]
                try:
                    geo_by_ip[ip] = fut.result()
                except Exception:
                    geo_by_ip[ip] = {'status': 'unavailable', 'ip': ip}

    # Trust boundary: walking from the most recent hop downward, the first
    # hop whose 'by' host is verifiable infrastructure.
    boundary_index = None
    for i, hop in enumerate(hops):
        if _host_is_trusted_relay(hop.get('by_host'), recipient_domain):
            boundary_index = i
            break

    annotated = []
    for i, hop in enumerate(hops):
        by_trusted = _host_is_trusted_relay(hop.get('by_host'), recipient_domain)
        past_boundary = boundary_index is not None and i > boundary_index
        status, reasons = _classify_hop(by_trusted, hop.get('by_host'), past_boundary)

        # Continuity check: this hop's 'from' should plausibly be the same
        # machine as the NEXT hop's 'by' (the next hop down is chronologically
        # earlier -- the one this hop claims it received the message from).
        consistent_with_next = None
        if i + 1 < len(hops):
            fh = _clean_host(hop.get('from_host'))
            nb = _clean_host(hops[i + 1].get('by_host'))
            if fh and nb:
                consistent_with_next = (fh == nb) or (fh in nb) or (nb in fh)
                if consistent_with_next is False and status == 'Trusted':
                    status = 'Suspicious'
                    reasons.append(
                        f"Claimed origin '{hop.get('from_host')}' does not match the next hop's "
                        f"receiving server '{hops[i + 1].get('by_host')}' -- possible inserted/forged header."
                    )

        primary_ip = hop['public_ips'][0] if hop.get('public_ips') else None
        geo = geo_by_ip.get(primary_ip) if primary_ip else None
        geo_ok = bool(geo and geo.get('status') == 'success')

        annotated.append({
            'hop_number': hop['hop_number'],
            'status': status,
            'reasons': reasons,
            'from_host': hop.get('from_host'),
            'by_host': hop.get('by_host'),
            'ip': primary_ip,
            'all_ips': hop.get('ips', []),
            'private_ip_only': bool(hop.get('ips')) and not hop.get('public_ips'),
            'country': geo.get('country') if geo_ok else None,
            'asn': geo.get('asn') if geo_ok else None,
            'isp': geo.get('isp') if geo_ok else None,
            'is_hosting_provider': geo.get('is_hosting_provider') if geo_ok else None,
            'timestamp': hop.get('timestamp'),
            'consistent_with_next_hop': consistent_with_next,
        })

    earliest_reliable_node = _build_earliest_reliable_node(
        hops, annotated, boundary_index, geo_by_ip
    )

    return {
        'trust_boundary_hop_number': hops[boundary_index]['hop_number'] if boundary_index is not None else None,
        'hops': annotated,
        'earliest_reliable_node': earliest_reliable_node,
    }


def _build_earliest_reliable_node(raw_hops, annotated, boundary_index, geo_by_ip):
    if boundary_index is not None:
        boundary_raw = raw_hops[boundary_index]
        boundary_annotated = annotated[boundary_index]
        node_ip = boundary_raw['public_ips'][0] if boundary_raw.get('public_ips') else None
        geo = geo_by_ip.get(node_ip) if node_ip else None
        confidence = _confidence_score(annotated, boundary_index, geo, verified=True)
        return {
            'ip': node_ip,
            'from_host': boundary_raw.get('from_host'),
            'verified_by': boundary_raw.get('by_host'),
            'country': geo.get('country') if geo and geo.get('status') == 'success' else None,
            'asn': geo.get('asn') if geo and geo.get('status') == 'success' else None,
            'isp': geo.get('isp') if geo and geo.get('status') == 'success' else None,
            'confidence': confidence,
            'unverified': False,
            'summary': _format_summary(node_ip, geo, confidence, unverified=False),
        }

    # No hop in the whole chain matched known/organizational infrastructure
    # -- there is no verified checkpoint at all. Fall back to the deepest
    # hop carrying a public IP (parser.py's own originating-IP heuristic)
    # but mark it explicitly as unverified with a low, honest confidence.
    fallback_ip = None
    fallback_hop = None
    for hop in reversed(raw_hops):
        if hop.get('public_ips'):
            fallback_ip = hop['public_ips'][0]
            fallback_hop = hop
            break
    if not fallback_ip:
        return None
    geo = geo_by_ip.get(fallback_ip)
    confidence = _confidence_score(annotated, None, geo, verified=False)
    return {
        'ip': fallback_ip,
        'from_host': fallback_hop.get('from_host'),
        'verified_by': None,
        'country': geo.get('country') if geo and geo.get('status') == 'success' else None,
        'asn': geo.get('asn') if geo and geo.get('status') == 'success' else None,
        'isp': geo.get('isp') if geo and geo.get('status') == 'success' else None,
        'confidence': confidence,
        'unverified': True,
        'summary': _format_summary(fallback_ip, geo, confidence, unverified=True),
    }


def _confidence_score(annotated_hops, boundary_index, geo, verified):
    """
    Deliberately simple and explainable (0-100) -- not a calibrated
    probability. Rewards: having an actual verified checkpoint, that
    checkpoint carrying a usable public IP, a successful GeoIP lookup,
    and hop-to-hop continuity; penalizes hosting/cloud-only attribution,
    failed lookups, and a long tail of untrusted self-reported hops.
    """
    score = 45 if verified else 20  # unverified fallback starts much lower

    boundary = annotated_hops[boundary_index] if boundary_index is not None else None
    has_ip = (boundary and boundary.get('ip')) if verified else (geo is not None)
    if has_ip:
        score += 15
    else:
        score -= 15

    geo_ok = bool(geo and geo.get('status') == 'success')
    if geo_ok:
        score += 15
        if geo.get('is_hosting_provider'):
            score -= 5  # generic hosting/cloud IP is weaker evidence of a true origin
    else:
        score -= 10

    if verified and boundary is not None:
        if boundary.get('consistent_with_next_hop') is True:
            score += 10
        elif boundary.get('consistent_with_next_hop') is False:
            score -= 15

        untrusted_after = sum(
            1 for h in annotated_hops[boundary_index + 1:] if h['status'] == 'Untrusted'
        )
        if untrusted_after > 3:
            score -= 5

    return max(5, min(97, score))


def _format_summary(ip, geo, confidence, unverified):
    if not ip:
        return "No public IP could be attributed to a reliable hop in this chain."
    geo_ok = bool(geo and geo.get('status') == 'success')
    location = f"{geo.get('country')}, {geo.get('asn')}" if geo_ok and geo.get('asn') else \
        (geo.get('country') if geo_ok else 'location unavailable')
    prefix = "Best-effort (unverified) source" if unverified else "Earliest reliable source"
    return f"{prefix}: {ip}, {location} — Confidence: {confidence}%"