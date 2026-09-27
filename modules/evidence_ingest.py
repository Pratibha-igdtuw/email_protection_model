"""
Multi-source evidence ingestion. USP: previously the platform only ever
accepted one evidence type -- a raw .eml/.txt email -- through /analyze.
This module is the generic counterpart used by the /evidence/upload
route: it validates the upload, computes a SHA-256 hash, and extracts
lightweight, evidence-type-appropriate metadata (EXIF + ELA tamper
detection for images; line/char counts + detected timestamps/phone
numbers for SMS exports and chat logs; PDF/Word tampering forensics for
documents; size/mime for anything else). The resulting hash then feeds
into the exact same chain_of_custody.build_custody_record() /
blockchain.add_block() pipeline already used for analyzed emails (see
app.py's /evidence/upload route) -- this module only handles the "what
is this file, and what can we say about it" half.
"""
import json
import mimetypes
import os
import re

from modules import document_forensics
from modules import image_forensics
from modules import ai_image_detection
from modules import classifier

EVIDENCE_TYPES = {
    'email': {
        'label': 'Email (.eml / .txt)',
        'extensions': {'.eml', '.txt'},
    },
    'sms_export': {
        'label': 'SMS export',
        'extensions': {'.txt', '.csv', '.xml', '.json'},
    },
    'chat_log': {
        'label': 'Chat log',
        'extensions': {'.txt', '.csv', '.json', '.html', '.htm'},
    },
    'image': {
        'label': 'Image / screenshot',
        'extensions': {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.tiff'},
    },
    'document': {
        'label': 'Document (PDF / Word)',
        'extensions': {'.pdf', '.docx', '.doc'},
    },
    'file': {
        'label': 'Other file',
        'extensions': None,  # no extension restriction -- last resort bucket
    },
}

# Generous but bounded -- screenshots and chat exports can be a few MB;
# this isn't meant to accept arbitrary large archives.
MAX_EVIDENCE_BYTES = 25 * 1024 * 1024

_PHONE_RE = re.compile(r'(\+?\d[\d\-\s()]{7,}\d)')
_DATE_RE = re.compile(
    r'\b(\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{2,4})\b'
)


def compute_sha256(raw_bytes):
    import hashlib
    return hashlib.sha256(raw_bytes).hexdigest()


def validate_upload(file_storage, evidence_type):
    """Returns an error message string if the upload should be rejected,
    or None if it's acceptable to ingest."""
    if evidence_type not in EVIDENCE_TYPES:
        return 'Choose an evidence type.'

    filename = file_storage.filename or ''
    ext = os.path.splitext(filename)[1].lower()
    allowed = EVIDENCE_TYPES[evidence_type]['extensions']
    if allowed is not None and ext not in allowed:
        label = EVIDENCE_TYPES[evidence_type]['label']
        return f"'{ext or '(no extension)'}' isn't an expected file type for {label}."

    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size == 0:
        return 'The uploaded file is empty.'
    if size > MAX_EVIDENCE_BYTES:
        return (f'File is too large ({size // (1024 * 1024)} MB) -- '
                f'max {MAX_EVIDENCE_BYTES // (1024 * 1024)} MB.')
    return None


def _extract_image_metadata(raw_bytes, filename):
    """EXIF + basic image properties, plus the same ELA/EXIF-consistency
    tamper check modules/image_forensics.py already runs on email
    attachments -- previously an image uploaded directly as standalone
    evidence only got a raw EXIF dump with no tampering analysis at all,
    which is exactly backwards for a forensics platform: standalone
    image evidence (screenshots, phone photos) is the case where "was
    this edited" matters most, not less, than an email attachment.
    Degrades gracefully -- most screenshots carry no EXIF at all, and
    Pillow may not be installed."""
    meta = {}
    try:
        import io as _io
        from PIL import Image
        from PIL.ExifTags import TAGS

        img = Image.open(_io.BytesIO(raw_bytes))
        meta['format'] = img.format
        meta['dimensions'] = f"{img.width}x{img.height}"
        meta['mode'] = img.mode

        exif_data = img.getexif()
        exif = {}
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                if isinstance(value, (bytes, bytearray)):
                    if len(value) > 100:
                        continue  # skip large binary blobs (e.g. embedded thumbnails)
                    value = value.hex()
                exif[str(tag)] = str(value)[:300]
        meta['has_exif'] = bool(exif)
        if exif:
            meta['exif'] = exif
    except ImportError:
        meta['note'] = ('Pillow is not installed, so EXIF could not be extracted -- '
                         'add Pillow to requirements.txt and reinstall to enable this.')
        return meta
    except Exception as e:
        meta['note'] = f'Could not parse image metadata: {e}'
        return meta

    tamper = image_forensics.analyze_image(raw_bytes, filename)
    if tamper.get('analyzed'):
        meta['tamper_analyzed'] = True
        if tamper.get('ela_info', {}).get('applicable') is not None:
            meta['ela_applicable'] = tamper['ela_info']['applicable']
        if tamper.get('flags'):
            meta['flags'] = tamper['flags']
        meta['tamper_risk_score'] = tamper.get('risk_score', 0)
    elif tamper.get('note'):
        # Don't overwrite an existing EXIF-parse note with this one --
        # keep whichever is more specific if both fired.
        meta.setdefault('note', tamper['note'])

    # AI-generated-image check -- deliberately stored under its own keys,
    # never merged into 'flags'/'tamper_risk_score' above. "This looks
    # AI-generated" and "this real photo was edited" are different
    # investigative findings; see modules/ai_image_detection.py.
    ai_gen = ai_image_detection.analyze_for_ai_generation(raw_bytes, filename)
    if ai_gen.get('analyzed'):
        meta['ai_generation_score'] = ai_gen['ai_generation_score']
        meta['likely_ai_generated'] = ai_gen['likely_ai_generated']
        if ai_gen.get('flags'):
            meta['ai_generation_flags'] = ai_gen['flags']
        if ai_gen.get('note'):
            meta['ai_generation_note'] = ai_gen['note']

    return meta


def _extract_text_metadata(raw_bytes):
    """Lightweight stats for SMS exports / chat logs. Counts detected
    timestamps/phone numbers rather than reproducing them in full, to
    keep the stored metadata small and avoid duplicating the evidence
    file's own content inside the DB."""
    try:
        text = raw_bytes.decode('utf-8', errors='replace')
    except Exception:
        return {'note': 'Could not decode file as text.'}

    lines = text.splitlines()
    dates_found = _DATE_RE.findall(text)
    phones_found = {p.strip() for p in _PHONE_RE.findall(text)}

    meta = {
        'line_count': len(lines),
        'char_count': len(text),
        'detected_timestamp_count': len(dates_found),
        'detected_phone_number_count': len(phones_found),
    }
    if dates_found:
        meta['first_detected_timestamp'] = dates_found[0]
        meta['last_detected_timestamp'] = dates_found[-1]
    if phones_found:
        # Bounded list of the actual numbers (not just a count) -- feeds
        # modules/correlation_graph.py, which needs real values to spot the
        # same number recurring across otherwise-unrelated evidence items.
        meta['detected_phone_numbers'] = sorted(phones_found)[:20]

    # AI/NLP fraud-likelihood scan -- previously SMS exports and chat logs
    # got no content analysis at all (just the stats above). Smishing/scam
    # chat text follows the same urgency-language + suspicious-link
    # playbook the trained phishing classifier already catches for email,
    # so it's run here too via classifier.classify_text_fragment().
    try:
        from modules import parser as parser_mod
        urls_in_text = parser_mod.extract_urls(text)
        scan = classifier.classify_text_fragment(text, urls_in_text)
        meta['fraud_likelihood_pct'] = scan['fraud_likelihood_pct']
        meta['ai_ml_probability'] = scan['ml_probability']
        if scan['flags']:
            meta['ai_flags'] = scan['flags']
    except Exception as e:
        meta['ai_scan_note'] = f'AI content scan could not run: {e}'

    return meta


def _extract_document_metadata(raw_bytes, filename):
    """PDF/Word tampering forensics (modules/document_forensics.py) --
    same creation/modification-date + editing-tool + incremental-update
    checks used for email attachments, applied here to a document
    ingested directly as its own piece of evidence."""
    result = document_forensics.analyze_document(raw_bytes, filename)
    meta = {'doc_type': result.get('doc_type')}
    for key in ('producer', 'creator', 'author', 'last_modified_by',
                'creation_date', 'modification_date', 'revision',
                'incremental_update_count'):
        if key in result and result[key] is not None:
            meta[key] = result[key]
    if result.get('flags'):
        meta['flags'] = result['flags']
    if result.get('note'):
        meta['note'] = result['note']
    return meta


def _extract_generic_metadata(filename):
    mime_type, _ = mimetypes.guess_type(filename or '')
    return {'guessed_mime_type': mime_type or 'application/octet-stream'}


def extract_metadata(raw_bytes, evidence_type, filename):
    if evidence_type == 'image':
        meta = _extract_image_metadata(raw_bytes, filename)
    elif evidence_type in ('sms_export', 'chat_log'):
        meta = _extract_text_metadata(raw_bytes)
    elif evidence_type == 'document':
        meta = _extract_document_metadata(raw_bytes, filename)
    else:
        meta = {}
    meta.update(_extract_generic_metadata(filename))
    meta['file_size_bytes'] = len(raw_bytes)
    return meta


def metadata_to_json(meta):
    return json.dumps(meta, default=str)