"""
Module: PDF / Office document tampering forensics

Same purpose as modules/image_forensics.py (ELA + EXIF consistency for
images) but for document attachments and uploaded document evidence:
verifying whether a PDF or Word file has been altered after it was first
produced, and what software last touched it -- signals that matter once a
document is being treated as forensic evidence (an "original" invoice,
contract, ID scan, etc.) rather than just a payload to malware-scan.

Three independent, well-established heuristics for PDFs:

  1. Creation vs. modification date mismatch -- a PDF's /CreationDate and
     /ModDate info-dictionary entries. A genuinely untouched, freshly
     generated PDF has these equal (or /ModDate absent); a later, different
     /ModDate means the file was opened and re-saved after it was first
     created.
  2. Producer/Creator software fingerprint -- flags known online PDF
     editors/converters (the tools most commonly used to alter or forge a
     document after the fact -- Smallpdf, iLovePDF, Sejda, PDFescape, Soda
     PDF, PDFsimpli, DocHub, PDFgear) as distinct from ordinary
     print-to-PDF/export producers (Word, Acrobat Distiller, LibreOffice,
     browsers). Naming an editor doesn't prove forgery -- plenty of
     legitimate edits go through them -- but it does mean the file is not a
     straight, untouched export.
  3. Incremental-update count -- a genuine PDF-format signal, not a
     heuristic guess: every time a PDF viewer/editor saves changes without
     fully rewriting the file (the default behavior for annotations, form
     fills, and signature additions), it appends a new revision plus another
     "%%EOF" marker rather than replacing the original bytes. Counting
     "%%EOF" occurrences in the raw file is a standard, well-documented way
     to detect this -- more than one means the file has at least one
     recorded revision after its initial save, which matters a lot for a
     document being presented as an unaltered original.

For Word documents (.docx), the OOXML core-properties stream records
created/modified timestamps, the declared author, and who last modified the
file -- so the same "was this touched after it was first made, and by
whom" question is asked there via python-docx instead of a PDF parser.
Legacy .doc (pre-2007 binary format) has no equivalent library available
here and is reported as unsupported rather than silently skipped.

Like image_forensics.py: heuristic red flags for an analyst to look at, not
proof of tampering. Degrades gracefully if pypdf/python-docx aren't
installed, or the file doesn't parse as a real PDF/DOCX.
"""
import re

PDF_EXTENSIONS = {'.pdf'}
DOCX_EXTENSIONS = {'.docx'}
LEGACY_DOC_EXTENSIONS = {'.doc', '.dot'}
DOCUMENT_EXTENSIONS = PDF_EXTENSIONS | DOCX_EXTENSIONS | LEGACY_DOC_EXTENSIONS

PDF_MIME_TYPES = {'application/pdf'}
DOCX_MIME_TYPES = {
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
}
LEGACY_DOC_MIME_TYPES = {'application/msword'}

# Online converters/editors commonly used to alter or forge a document after
# its original creation -- distinct from ordinary export/print producers
# (Microsoft Word, Acrobat Distiller, LibreOffice, browser print-to-PDF)
# which are not flagged.
EDITOR_TOOL_MARKERS = (
    'smallpdf', 'ilovepdf', 'sejda', 'pdfescape', 'soda pdf', 'sodapdf',
    'pdfsimpli', 'dochub', 'pdfgear', 'pdfelement', 'pdf-xchange editor',
    'foxit phantompdf', 'jotform', 'signnow', 'pdfcandy', 'pdf24',
)

DATE_MISMATCH_SCORE = 6
EDITOR_TOOL_SCORE = 5
INCREMENTAL_UPDATE_SCORE = 10
DOCX_AUTHOR_MISMATCH_SCORE = 6
DOCX_MODIFIED_SCORE = 4


def _get_extension(filename):
    if not filename or '.' not in filename:
        return ''
    return '.' + filename.rsplit('.', 1)[-1].lower()


def is_document(filename, content_type):
    """Cheap pre-check so attachment_scan.py only pays the parse cost for
    attachments that plausibly are PDFs or Word documents."""
    ext = _get_extension(filename)
    ctype = (content_type or '').lower()
    return (
        ext in DOCUMENT_EXTENSIONS
        or ctype in PDF_MIME_TYPES
        or ctype in DOCX_MIME_TYPES
        or ctype in LEGACY_DOC_MIME_TYPES
    )


def _doc_kind(filename, content_type):
    ext = _get_extension(filename)
    ctype = (content_type or '').lower()
    if ext in PDF_EXTENSIONS or ctype in PDF_MIME_TYPES:
        return 'pdf'
    if ext in DOCX_EXTENSIONS or ctype in DOCX_MIME_TYPES:
        return 'docx'
    if ext in LEGACY_DOC_EXTENSIONS or ctype in LEGACY_DOC_MIME_TYPES:
        return 'legacy_doc'
    return None


_PDF_DATE_RE = re.compile(
    r"D:(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?"
)


def _parse_pdf_date(raw):
    """PDF info-dictionary dates look like 'D:20230115120000+05'30''.
    Returns an ISO-ish string for display, or None if unparseable/absent."""
    if not raw:
        return None
    m = _PDF_DATE_RE.match(str(raw))
    if not m:
        return str(raw)  # non-standard but keep whatever was there, for display
    year, month, day, hh, mm, ss = m.groups()
    hh, mm, ss = hh or '00', mm or '00', ss or '00'
    return f"{year}-{month}-{day} {hh}:{mm}:{ss}"


def _analyze_pdf(payload, filename):
    result = {
        'doc_type': 'pdf', 'analyzed': False, 'producer': None, 'creator': None,
        'creation_date': None, 'modification_date': None,
        'incremental_update_count': None, 'flags': [], 'risk_score': 0, 'note': None,
    }
    try:
        from pypdf import PdfReader
    except ImportError:
        result['note'] = ('pypdf is not installed, so PDF tampering checks could not run -- '
                           'add pypdf to requirements.txt and reinstall to enable this.')
        return result

    # Computed on the raw bytes, independent of whether pypdf can fully
    # parse the file below -- a malformed/truncated xref chain is itself
    # sometimes a symptom of a botched incremental edit, so this shouldn't
    # be gated on a successful full parse.
    eof_count = payload.count(b'%%EOF')

    import io
    try:
        reader = PdfReader(io.BytesIO(payload))
        info = reader.metadata or {}
    except Exception as e:
        result['analyzed'] = True
        result['note'] = f'Could not fully parse "{filename}" as a PDF (metadata unavailable): {e}'
        result['incremental_update_count'] = max(eof_count - 1, 0)
        if eof_count > 1:
            result['flags'] = [
                f"File contains {eof_count} '%%EOF' markers ({eof_count - 1} incremental "
                f"update(s) after the initial save) -- content was appended/changed post-creation "
                f"rather than the file being a single untouched save"]
            result['risk_score'] = INCREMENTAL_UPDATE_SCORE
        return result

    result['analyzed'] = True
    flags = []
    score = 0

    producer = str(info.get('/Producer') or '') or None
    creator = str(info.get('/Creator') or '') or None
    result['producer'] = producer
    result['creator'] = creator

    combined_tool_string = f"{producer or ''} {creator or ''}".lower()
    if any(marker in combined_tool_string for marker in EDITOR_TOOL_MARKERS):
        matched = next(m for m in EDITOR_TOOL_MARKERS if m in combined_tool_string)
        flags.append(
            f"Producer/Creator names an online PDF editor ('{matched}') -- "
            f"file has been through an editing/conversion tool, not just generated once")
        score += EDITOR_TOOL_SCORE

    created_raw = info.get('/CreationDate')
    modified_raw = info.get('/ModDate')
    created = _parse_pdf_date(created_raw)
    modified = _parse_pdf_date(modified_raw)
    result['creation_date'] = created
    result['modification_date'] = modified
    if created and modified and created != modified:
        flags.append(
            f"PDF modification date ({modified}) differs from the creation date "
            f"({created}) -- file was opened and re-saved after it was first created")
        score += DATE_MISMATCH_SCORE

    result['incremental_update_count'] = max(eof_count - 1, 0)
    if eof_count > 1:
        flags.append(
            f"File contains {eof_count} '%%EOF' markers ({eof_count - 1} incremental "
            f"update(s) after the initial save) -- content was appended/changed post-creation "
            f"rather than the file being a single untouched save")
        score += INCREMENTAL_UPDATE_SCORE

    result['flags'] = flags
    result['risk_score'] = score
    return result


def _analyze_docx(payload, filename):
    result = {
        'doc_type': 'docx', 'analyzed': False, 'author': None, 'last_modified_by': None,
        'creation_date': None, 'modification_date': None, 'revision': None,
        'flags': [], 'risk_score': 0, 'note': None,
    }
    try:
        import docx
    except ImportError:
        result['note'] = ('python-docx is not installed, so Word document tampering checks '
                           'could not run -- add python-docx to requirements.txt and reinstall '
                           'to enable this.')
        return result

    import io
    try:
        doc = docx.Document(io.BytesIO(payload))
        props = doc.core_properties
    except Exception as e:
        result['note'] = f'Could not parse "{filename}" as a .docx file: {e}'
        return result

    result['analyzed'] = True
    flags = []
    score = 0

    author = props.author or None
    last_modified_by = props.last_modified_by or None
    created = props.created
    modified = props.modified
    result['author'] = author
    result['last_modified_by'] = last_modified_by
    result['creation_date'] = created.strftime('%Y-%m-%d %H:%M:%S') if created else None
    result['modification_date'] = modified.strftime('%Y-%m-%d %H:%M:%S') if modified else None
    result['revision'] = props.revision

    if created and modified and created != modified:
        flags.append(
            f"Document modified date ({result['modification_date']}) differs from the created "
            f"date ({result['creation_date']}) -- file was edited after it was first authored")
        score += DOCX_MODIFIED_SCORE

    if author and last_modified_by and author.strip().lower() != last_modified_by.strip().lower():
        flags.append(
            f"Last modified by '{last_modified_by}' differs from the declared author "
            f"'{author}' -- someone other than the original author edited this file")
        score += DOCX_AUTHOR_MISMATCH_SCORE

    result['flags'] = flags
    result['risk_score'] = score
    return result


def analyze_document(payload, filename, content_type=None):
    """
    payload: raw file bytes (may be None/empty).
    filename: original filename, used to route to the PDF/DOCX parser and
        for error messages.

    Returns a dict; shape depends on doc_type but always includes
    'doc_type', 'analyzed', 'flags', 'risk_score', 'note'. 'note' is set
    when the check could not run at all (missing library, unsupported
    legacy .doc, payload missing, file doesn't parse) -- distinct from a
    normal "analyzed successfully, nothing flagged" result.
    """
    base = {'doc_type': None, 'analyzed': False, 'flags': [], 'risk_score': 0, 'note': None}
    if not payload:
        base['note'] = 'No attachment content available to analyze.'
        return base

    kind = _doc_kind(filename, content_type)
    if kind == 'pdf':
        return _analyze_pdf(payload, filename)
    if kind == 'docx':
        return _analyze_docx(payload, filename)
    if kind == 'legacy_doc':
        base['doc_type'] = 'legacy_doc'
        base['note'] = ('Legacy .doc (pre-2007 binary Word format) metadata forensics is not '
                         'supported here -- convert to .docx or PDF for a tampering check.')
        return base

    base['note'] = f'"{filename}" is not a recognized PDF or Word document.'
    return base