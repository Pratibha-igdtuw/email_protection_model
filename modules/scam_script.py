"""
Scam-script analyzer for phone calls: given what the caller SAID (typed or
dictated by the person who got the call), scores it against the scripts
that real phone scams follow.

Why this is often more reliable than checking the number: scammers rotate
numbers constantly and spoof caller ID, so a fresh scam number has no
reports -- but the script barely changes. A call is judged on tactics no
genuine bank, police officer, courier or government office uses:
asking for an OTP/PIN/CVV, asking you to install a screen-sharing app,
"digital arrest" threats, "safe account" transfers, demands for secrecy.

English and common Hindi/Hinglish phrasings are covered. It is rule-based
and explainable (every match is shown back), deliberately NOT a black box:
a person should see exactly which sentence triggered which warning.
"""
import re

# category -> (weight, plain-language explanation, regex)
_CATEGORIES = {
    'secret_codes': (40, "Asked for an OTP, PIN, CVV, password or card details. No bank, government office or company ever asks for these on a call.",
        r"\botp\b|one[\s-]?time[\s-]?(?:password|code)|\bcvv\b|\bupi[\s-]?pin\b|\batm[\s-]?pin\b|\bpin\b(?:\s+(?:number|code))?|card\s+number|expiry\s+date|net\s*banking\s+password|share\s+(?:the\s+)?code|"
        r"(?:otp|pin|cvv)\s*(?:bata|batao|bolo|share\s*karo|send\s*karo)|(?:code|otp)\s+jo\s+aaya"),
    'remote_access': (35, "Asked you to install an app or share your screen. Scammers use these (AnyDesk, TeamViewer, QuickSupport, APK files) to see your screen and empty your bank account.",
        r"any\s*desk|team\s*viewer|quick\s*support|rust\s*desk|\bammyy\b|screen\s*shar|share\s+your\s+screen|\bapk\b|install\s+(?:this|the|an?)\s+app|download\s+(?:this|the|an?)\s+app|app\s+(?:install|download)\s+karo|play\s*store\s+se\s+download"),
    'authority_threat': (30, "Claims to be police, CBI, ED, customs, TRAI, a courier or court and threatens arrest or action ('digital arrest' is always a scam -- there is no such thing).",
        r"digital\s+arrest|arrest\s+warrant|\bcbi\b|enforcement\s+directorate|\bed\s+officer|narcotics|money\s+laundering|cyber\s*crime\s+(?:branch|police|department)|customs\s+(?:officer|department)|\btrai\b|"
        r"parcel\s+(?:has\s+been\s+)?(?:seized|held|stopped)|fed\s*ex|aadhaar\s+(?:is\s+)?(?:misused|linked\s+to)|(?:you\s+(?:will\s+be|are\s+being)|aapko)\s+arrest|giraftar|court\s+(?:case|notice|summons)"),
    'account_block': (25, "Threatens that your account, SIM, KYC or card will be blocked/suspended unless you act now.",
        r"\bkyc\b|(?:account|sim|card|number)\s+(?:will\s+be\s+|is\s+(?:being\s+)?|has\s+been\s+)?(?:block(?:ed)?|suspend(?:ed)?|freez(?:e|ing)|frozen|deactivat(?:ed|e)|disconnect(?:ed)?)|link\s+(?:your\s+)?(?:aadhaar|pan)|pan\s+(?:card\s+)?update|band\s+ho\s+jaye"),
    'money_demand': (35, "Asks you to send money -- a 'fee', 'deposit', 'safe account', gift card, crypto or a UPI collect/QR request. Receiving money never needs you to scan a QR or approve a request.",
        r"safe\s+account|transfer\s+(?:the\s+)?(?:money|amount|funds)|send\s+(?:the\s+)?(?:money|amount)|(?:processing|registration|refund|clearance|verification|security)\s+(?:fee|charge|deposit|amount)|gift\s*card|bitcoin|crypto|western\s+union|"
        r"upi\s+(?:collect|request)|scan\s+(?:this\s+)?(?:the\s+)?qr|paisa\s+(?:bhej|transfer)|rbi\s+(?:account|safe)"),
    'prize_job': (25, "Promises a prize, lottery, refund, loan or easy job/'task' income. These are the bait in most phone and chat scams.",
        r"lottery|you\s+(?:have\s+)?won|lucky\s+draw|\bkbc\b|work\s+from\s+home|part[\s-]?time\s+job|earn\s+(?:rs\.?|₹)?\s*\d+|(?:pre[\s-]?approved|instant)\s+loan|cashback\s+(?:offer|reward)|inaam|jeet\s+gaye"),
    'urgency': (15, "Pressures you to act immediately or not to hang up -- scammers rush you so you can't think or ask anyone.",
        r"immediately|right\s+now|urgent(?:ly)?|within\s+\d+\s+(?:hours?|minutes?)|last\s+chance|don'?t\s+(?:hang\s+up|disconnect|cut\s+the\s+call)|stay\s+on\s+the\s+line|abhi\s+ke\s+abhi|turant|jaldi|call\s+(?:mat\s+)?kaat"),
    'secrecy': (25, "Tells you to keep it secret or not to tell family/the bank. Genuine officials never ask this; scammers do to stop anyone warning you.",
        r"(?:don'?t|do\s+not|never)\s+(?:tell|inform|share\s+with)\s+(?:anyone|anybody|your\s+family|the\s+bank)|keep\s+(?:this|it)\s+(?:a\s+)?(?:secret|confidential)|confidential\s+matter|kisi\s+ko\s+(?:mat\s+)?(?:bata|batana)|ghar\s+(?:walon\s+)?ko\s+mat"),
    'bank_impersonation': (10, "Says they are 'calling from your bank' / customer care. Verify by calling the number printed on your card or the bank's official site -- never the number the caller gives.",
        r"calling\s+from\s+(?:your\s+)?(?:bank|sbi|hdfc|icici|axis|amazon|paytm|phonepe|google\s*pay)|(?:bank|customer\s+care)\s+(?:manager|executive|officer)|bank\s+se\s+bol"),
}

_COMPILED = {k: (w, why, re.compile(rx, re.IGNORECASE)) for k, (w, why, rx) in _CATEGORIES.items()}

LABELS = {
    'secret_codes': 'Asks for OTP / PIN / CVV / password', 'remote_access': 'Asks you to install an app / share screen',
    'authority_threat': 'Fake authority & arrest threat', 'account_block': 'Account / SIM / KYC block threat',
    'money_demand': 'Demands money / unusual payment', 'prize_job': 'Prize, lottery, loan or job bait',
    'urgency': 'Urgency & pressure', 'secrecy': 'Demands secrecy', 'bank_impersonation': 'Claims to be your bank',
}


def analyze_call_script(text):
    """Returns {'status': 'empty'|'success', 'score', 'severity', 'matches': [...], 'advice'}."""
    text = (text or '').strip()
    if not text:
        return {'status': 'empty'}

    matches, score = [], 0
    for key, (weight, why, rx) in _COMPILED.items():
        hits = []
        for m in rx.finditer(text):
            phrase = m.group(0).strip()
            if phrase.lower() not in [h.lower() for h in hits]:
                hits.append(phrase)
        if hits:
            score += weight
            matches.append({'category': key, 'label': LABELS[key], 'why': why, 'phrases': hits[:4], 'weight': weight})

    if len(matches) >= 3:
        score += 10                      # several different tactics together is the real fingerprint of a script
    score = min(score, 100)
    severity = 'HIGH' if score >= 60 else ('MEDIUM' if score >= 30 else 'LOW')

    # A single "never legitimate" ask is enough on its own to treat the call as dangerous.
    if any(m['category'] in ('secret_codes', 'remote_access') for m in matches):
        severity = 'HIGH'
        score = max(score, 60)

    matches.sort(key=lambda m: -m['weight'])
    advice = ("Hang up now. Do not share any code, do not install anything, and do not transfer money. "
              "Call your bank on the number printed on your card, and report it at cybercrime.gov.in or call 1930."
              if severity in ('HIGH', 'MEDIUM') else
              "Nothing in this text matches a known scam script, but that is not a guarantee. "
              "If the caller asked for money or codes, treat it as a scam regardless.")
    return {'status': 'success', 'score': score, 'severity': severity, 'matches': matches, 'advice': advice}
