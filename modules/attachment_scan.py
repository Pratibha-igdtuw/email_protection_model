"""
Module: Attachment risk analysis
Flags attachments for common malware-delivery patterns: dangerous
executable/script file types, the classic "invoice.pdf.exe" double-extension
disguise, macro-enabled Office documents, archives (contents not inspected),
and a declared MIME type that doesn't match an otherwise-safe-looking
filename. This is heuristic red-flagging consistent with the rest of this
pipeline (SPF/DKIM/domain-age/etc. are all heuristics too) -- it points an
analyst at what to look at, not a malware-scanning/AV engine with signature
matching, and it does not claim to be one.
"""
import re

DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.msi', '.jar', '.ps1', '.ps1xml',
    '.reg', '.lnk', '.hta', '.cpl', '.msc', '.gadget', '.vb', '.vbscript',
}

MACRO_ENABLED_EXTENSIONS = {
    '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm', '.xlsb', '.sldm',
}

ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.iso', '.img', '.cab', '.ace'}

# Declared content-types that commonly get used to disguise an executable
# payload behind an innocuous-looking filename.
EXECUTABLE_MIME_TYPES = {
    'application/x-msdownload', 'application/x-msdos-program',
    'application/x-executable', 'application/x-dosexec',
}


def _get_extension(filename):
    if not filename:
        return ''
    m = re.search(r'(\.[a-zA-Z0-9]{1,6})$', filename)
    return m.group(1).lower() if m else ''


def _has_double_extension(filename):
    """Classic disguise trick: 'invoice.pdf.exe' -- a filename with 2+
    dot-separated segments where the LAST extension is a dangerous type
    (so the visible/earlier part can look like a harmless document)."""
    if not filename:
        return False
    parts = filename.split('.')
    if len(parts) < 3:
        return False
    return ('.' + parts[-1].lower()) in DANGEROUS_EXTENSIONS


def analyze_attachments(parsed_attachments):
    """
    parsed_attachments: list of dicts with filename/content_type/size_bytes/
    sha256, as produced by parser.py.

    Returns {'attachments': [...with risk flags added...], 'count': int,
             'risk_score': int (0-15), 'flags': [human-readable strings]}.
    risk_score is the WORST single attachment's score, not a sum across
    attachments -- an email with five ordinary PDFs shouldn't score higher
    than one with a single disguised .exe just because it has more files.
    """
    results = []
    flags = []
    worst_score = 0

    for att in (parsed_attachments or []):
        filename = att.get('filename') or ''
        content_type = (att.get('content_type') or '').lower()
        ext = _get_extension(filename)

        is_dangerous_ext = ext in DANGEROUS_EXTENSIONS
        is_double_ext = _has_double_extension(filename)
        is_macro = ext in MACRO_ENABLED_EXTENSIONS
        is_archive = ext in ARCHIVE_EXTENSIONS
        mime_mismatch = content_type in EXECUTABLE_MIME_TYPES and not is_dangerous_ext

        att_flags = []
        att_score = 0
        if is_dangerous_ext:
            att_flags.append(f"Dangerous executable/script file type ({ext})")
            att_score += 15
        if is_double_ext:
            att_flags.append(f"Double-extension disguise pattern: \"{filename}\"")
            att_score += 15
        if is_macro:
            att_flags.append(f"Macro-enabled Office document ({ext}) -- can execute code on open")
            att_score += 10
        if is_archive:
            att_flags.append(f"Archive file ({ext}) -- contents not inspected, manual review recommended")
            att_score += 4
        if mime_mismatch:
            att_flags.append(f"Declared content-type ({content_type}) is inconsistent with a safe document")
            att_score += 8

        results.append({
            **att,
            'extension': ext,
            'is_dangerous_extension': is_dangerous_ext,
            'is_double_extension': is_double_ext,
            'is_macro_enabled': is_macro,
            'is_archive': is_archive,
            'mime_mismatch': mime_mismatch,
            'risk_flags': att_flags,
        })
        flags.extend(f"{filename}: {f}" for f in att_flags)
        worst_score = max(worst_score, att_score)

    return {
        'attachments': results,
        'count': len(results),
        'risk_score': min(worst_score, 15),
        'flags': flags,
    }