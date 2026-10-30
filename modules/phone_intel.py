"""
Phone number intelligence beyond "is it on a blacklist" -- the structural
facts about a number that are very hard for a scammer to fake:

  - Offline profile via Google's libphonenumber (`phonenumbers`, no network):
    is the number even valid, which country/region and carrier, and what KIND
    of line it is -- mobile, landline, toll-free, premium-rate, or an
    internet (VoIP) number. Banks, police and government offices call from
    ordinary landline/mobile/toll-free numbers; spoofed and throw-away scam
    calls disproportionately come from VoIP and foreign numbers.
  - Optional live line-type lookup via Veriphone (VERIPHONE_API_KEY, free
    plan: 1,000 lookups/month, no card): tells genuine mobile/landline apart
    from VoIP numbers that anyone can create in minutes.

Every signal here is context for a human, not proof: a VoIP number can be a
legitimate business and a scammer can use a real mobile SIM. Signals are
returned as {'name','level','text'} (level: bad / warn / ok / info) and add
only modest points to the overall phone score (see apply_to_score).
"""
import os

import requests

try:
    import phonenumbers
    from phonenumbers import PhoneNumberType as T
    from phonenumbers import carrier as _carrier
    from phonenumbers import geocoder as _geocoder
    from phonenumbers import timezone as _timezone
    _HAS = True
except ImportError:  # pragma: no cover
    _HAS = False

VERIPHONE_URL = "https://api.veriphone.io/v3/verify"
DEFAULT_TIMEOUT = 5


def home_region():
    return (os.environ.get('DEFAULT_PHONE_REGION') or 'IN').upper()


def _sig(name, level, text):
    return {'name': name, 'level': level, 'text': text}


def offline_profile(e164):
    """Structural profile of the number, offline. Returns
    {'status': 'success'|'unavailable', 'signals': [...], plus facts}."""
    if not _HAS or not e164:
        return {'status': 'unavailable', 'signals': []}
    try:
        parsed = phonenumbers.parse(e164, None)
    except Exception:
        return {'status': 'unavailable', 'signals': []}

    region = phonenumbers.region_code_for_number(parsed)
    ntype = phonenumbers.number_type(parsed)
    names = {T.MOBILE: 'mobile', T.FIXED_LINE: 'landline', T.FIXED_LINE_OR_MOBILE: 'mobile or landline',
             T.TOLL_FREE: 'toll-free', T.PREMIUM_RATE: 'premium-rate', T.SHARED_COST: 'shared-cost',
             T.VOIP: 'VoIP (internet number)', T.PERSONAL_NUMBER: 'personal number', T.PAGER: 'pager',
             T.UAN: 'company-wide (UAN) number', T.VOICEMAIL: 'voicemail', T.UNKNOWN: 'unknown'}
    type_name = names.get(ntype, 'unknown')
    valid = phonenumbers.is_valid_number(parsed)
    carrier = _carrier.name_for_number(parsed, 'en') or None
    place = _geocoder.description_for_number(parsed, 'en') or None
    zones = list(_timezone.time_zones_for_number(parsed))[:2]

    sigs = []
    if not valid:
        sigs.append(_sig('invalid', 'bad', 'This is not a valid phone number for its country -- a real caller cannot have it. Caller ID may be faked.'))
    if ntype == T.PREMIUM_RATE:
        sigs.append(_sig('premium_rate', 'bad', 'This is a premium-rate number: calling it back can charge you heavily (common in "missed call" scams).'))
    elif ntype == T.VOIP:
        sigs.append(_sig('voip', 'warn', 'This is an internet (VoIP) number. These are easy to create and spoof, and banks or government offices rarely call from them.'))
    elif ntype == T.SHARED_COST:
        sigs.append(_sig('shared_cost', 'warn', 'This is a shared-cost number, not an ordinary mobile or landline.'))
    elif ntype in (T.MOBILE, T.FIXED_LINE, T.FIXED_LINE_OR_MOBILE):
        sigs.append(_sig('line_type', 'info', f'Ordinary {type_name} number' + (f' ({carrier})' if carrier else '') + '.'))
    elif ntype == T.TOLL_FREE:
        sigs.append(_sig('toll_free', 'info', 'Toll-free number. Real companies use these, but scammers can spoof them too.'))

    home = home_region()
    if region and region != home and valid:
        sigs.append(_sig('foreign', 'warn',
                         f'This number is from {place or region} ({region}), not {home}. A foreign number claiming to be your local '
                         'bank, police, courier or a government office is a strong scam sign.'))
    return {'status': 'success', 'valid': valid, 'region': region, 'type': type_name,
            'carrier': carrier, 'place': place, 'timezones': zones, 'signals': sigs}


def live_line_type(e164, timeout=DEFAULT_TIMEOUT):
    """Optional live lookup (Veriphone, free tier). Never raises."""
    key = os.environ.get('VERIPHONE_API_KEY')
    if not key:
        return {'status': 'not_configured', 'signals': []}
    try:
        resp = requests.get(VERIPHONE_URL, params={'phone': e164},
                            headers={'Authorization': f'Bearer {key}'}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get('status') != 'success':
            return {'status': 'unavailable', 'message': str(data.get('message') or data.get('status'))[:200], 'signals': []}
        ltype = (data.get('phone_type') or '').lower() or None
        carrier = data.get('carrier') or None
        sigs = []
        if data.get('phone_valid') is False:
            sigs.append(_sig('live_unknown', 'warn', 'Live lookup: this number is not valid / not in use on any carrier network.'))
        elif ltype == 'voip':
            sigs.append(_sig('live_voip', 'warn', 'Live lookup: this is an internet (VoIP) number -- anyone can get one in minutes, a favourite of scammers.'))
        elif ltype:
            label = ltype.replace('_', ' ')
            sigs.append(_sig('live_type', 'info', f"Live lookup: {label} line" + (f" on {carrier}" if carrier else '') + '.'))
        return {'status': 'success', 'type': ltype, 'carrier': carrier, 'signals': sigs}
    except requests.exceptions.RequestException as e:
        return {'status': 'unavailable', 'message': str(e)[:200], 'signals': []}
    except (ValueError, TypeError) as e:
        return {'status': 'unavailable', 'message': f'Unexpected response: {e}', 'signals': []}


def apply_to_score(profile, live):
    """Modest additive points from the structural signals (never enough on
    their own to reach HIGH): returns (points, reasons)."""
    points, reasons = 0, []
    names = {s['name'] for s in (profile or {}).get('signals', [])} | {s['name'] for s in (live or {}).get('signals', [])}
    if 'premium_rate' in names:
        points += 25; reasons.append('Premium-rate number (calling back can be costly)')
    if 'invalid' in names:
        points += 20; reasons.append('Not a valid number for its country (caller ID likely faked)')
    if names & {'voip', 'live_voip'}:
        points += 10; reasons.append('Internet (VoIP) number -- easy to create and spoof')
    if 'foreign' in names:
        points += 10; reasons.append('Foreign number (unexpected for a local bank / office / courier)')
    if 'live_unknown' in names:
        points += 10; reasons.append('Live lookup: number not valid / not in use on any carrier')
    return points, reasons
