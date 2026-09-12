"""
Module 2: GeoLocation Intelligence
Uses ipwho.is (free tier, no key needed, HTTPS) for IP -> location/ASN/ISP
lookup. ip-api.com was used previously but its free tier is HTTP-only --
sending the IP under investigation in cleartext and giving no way to
detect a MITM tampering with the response that feeds the risk score.
Falls back gracefully to a "lookup unavailable" stub if offline, rate
limited, or the response shape is unexpected, so the rest of the
pipeline never breaks because of this module.
"""
import requests

IP_LOOKUP_API = "https://ipwho.is/{ip}"


def lookup_ip(ip_address, timeout=4):
    if not ip_address:
        return {'status': 'no_ip', 'message': 'No originating IP could be extracted from headers.'}
    try:
        resp = requests.get(IP_LOOKUP_API.format(ip=ip_address), timeout=timeout)
        data = resp.json()
        if not data.get('success', False):
            return {'status': 'failed', 'message': data.get('message', 'lookup failed'), 'ip': ip_address}
        connection = data.get('connection') or {}
        security = data.get('security') or {}
        asn = connection.get('asn')
        return {
            'status': 'success',
            'ip': ip_address,
            'country': data.get('country'),
            'country_code': data.get('country_code'),
            'region': data.get('region'),
            'city': data.get('city'),
            'zip': data.get('postal'),
            'lat': data.get('latitude'),
            'lon': data.get('longitude'),
            'isp': connection.get('isp'),
            'org': connection.get('org'),
            'asn': f"AS{asn}" if asn else None,
            'as_name': connection.get('org'),
            'is_proxy_or_vpn': bool(security.get('proxy') or security.get('vpn')),
            'is_hosting_provider': bool(security.get('hosting')),
        }
    except Exception as e:
        return {'status': 'unavailable', 'message': f'GeoIP lookup unavailable ({e.__class__.__name__}). '
                                                      f'Check network access / API rate limits.', 'ip': ip_address}


def check_brand_mismatch(claimed_brand_domain, geo_result, known_brand_countries=None):
    """
    Simple heuristic: if sender claims to be a well-known brand but the
    resolving IP's org/ISP/country doesn't match anything plausible for
    that brand, flag it. `known_brand_countries` is an optional list of
    expected country codes for the claimed brand (caller can supply from
    a lookup table); if not supplied, we just report facts without judging.
    """
    if geo_result.get('status') != 'success':
        return {'mismatch_detected': False, 'reason': 'geo data unavailable'}

    if known_brand_countries:
        if geo_result.get('country_code') not in known_brand_countries:
            return {
                'mismatch_detected': True,
                'reason': f"Domain '{claimed_brand_domain}' resolved to {geo_result.get('country')} "
                          f"({geo_result.get('isp')}), which is not an expected region for this brand."
            }
    if geo_result.get('is_hosting_provider'):
        return {
            'mismatch_detected': True,
            'reason': f"Sending IP belongs to a generic hosting/cloud provider "
                      f"({geo_result.get('org') or geo_result.get('isp')}) rather than a corporate mail network — "
                      f"common in spoofed/mass-mail campaigns."
        }
    return {'mismatch_detected': False, 'reason': None}