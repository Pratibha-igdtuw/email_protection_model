"""
Module: Image tampering forensics (Error Level Analysis + EXIF consistency)

Strengthens attachment_scan.py's evidence-authenticity checks for image
attachments. That module previously only looked at filename/MIME-type
heuristics (double extensions, dangerous extensions) -- useful for malware
delivery, but blind to whether an *image itself* has been edited after the
fact, which matters for "verifying evidence integrity and origin" once an
image is being treated as forensic evidence rather than just a payload to
scan for malware.

Two independent, well-established heuristics:

  1. Error Level Analysis (ELA) -- re-saves the image at a known JPEG
     quality and diffs it against the original. A region that was pasted
     in (or edited and re-saved) usually carries a different prior
     compression history than the rest of the frame, so it settles to a
     visibly different error level under a fresh re-compression -- a
     genuinely untouched JPEG shows fairly even error levels everywhere.
     Only meaningful for JPEG: lossless formats (PNG/GIF/BMP) have no
     compression-generation signal to diff against, so ELA is skipped for
     those and that is reported explicitly rather than silently returning
     a falsely "clean" result.
  2. EXIF consistency -- flags an EXIF Software tag naming a known
     editing tool, and a modify timestamp that postdates the original
     capture timestamp -- i.e. "this file was opened and re-saved by an
     editor after it was created."

Like the rest of this pipeline (SPF/DKIM/domain-age/attachment-extension
checks), these are heuristic red flags for an analyst to look at, not
proof of tampering: a clean result does not certify authenticity, and a
flagged result does not prove forgery (ordinary resizing/rotation tools,
or a phone's camera app itself, can also touch these signals). Degrades
gracefully -- if Pillow isn't installed, or the file isn't a real
decodable image, that is reported and the check contributes zero score
rather than raising.
"""
import base64
import io
import re

IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.webp'}

# Editing tools that have no business appearing in the EXIF of an image
# being presented as an unaltered original (a straight-from-camera or
# straight-from-messaging-app file).
EDITING_SOFTWARE_MARKERS = (
    'photoshop', 'gimp', 'lightroom', 'snapseed', 'pixelmator',
    'paint.net', 'affinity photo', 'canva', 'picsart', 'facetune',
    'photoscape', 'paintshop', 'krita', 'inkscape',
)

ELA_JPEG_QUALITY = 90
# Empirically-reasonable thresholds, not a calibrated forensic standard.
# A genuinely untouched JPEG re-compresses fairly evenly across the whole
# frame; a big gap between the *peak* per-pixel error and the *typical*
# (mean) error suggests one localized region was compressed differently
# from the rest -- consistent with a splice/edit, though not exclusively
# caused by one. The mean_err<40 guard on the caller side exists because a
# generally busy/high-detail/heavily-recompressed image can have high
# error levels everywhere, which is a different (non-localized) pattern
# than what ELA is meant to catch.
ELA_ANOMALY_RATIO_THRESHOLD = 6.0
ELA_ANOMALY_MEAN_CEILING = 40.0
ELA_MIN_MEAN_FOR_RATIO = 1.0  # avoid a divide-by-near-zero blowup on near-blank images

SOFTWARE_TAG_SCORE = 8
XMP_CREATOR_TOOL_SCORE = 8
TIMESTAMP_MISMATCH_SCORE = 6
ELA_ANOMALY_SCORE = 10


def is_image(filename, content_type):
    """Cheap pre-check so attachment_scan.py only pays the decode cost for
    attachments that plausibly are images."""
    ext = ''
    if filename and '.' in filename:
        ext = '.' + filename.rsplit('.', 1)[-1].lower()
    ctype = (content_type or '').lower()
    return ext in IMAGE_EXTENSIONS or ctype.startswith('image/')


def _channel_mean(channel_histogram):
    """Mean pixel value from one channel's 256-bucket histogram, without
    a numpy dependency -- Pillow is already a requirement, numpy isn't."""
    total = sum(channel_histogram)
    if not total:
        return 0.0
    weighted = sum(intensity * count for intensity, count in enumerate(channel_histogram))
    return weighted / total


def _check_xmp_editor(img):
    """Returns (flags, info). Design tools like Canva compose a final
    image from a flat canvas and re-export it as one clean,
    single-generation file -- there's no differential compression
    history left for ELA to find, and most of these tools don't touch
    the classic EXIF 'Software' tag either. But several (Canva
    included) write their name into the XMP CreatorTool field instead,
    a completely separate metadata block that _check_exif_consistency's
    img.getexif() call never sees. Same idea as that check, aimed at
    the right metadata block for tools that use it."""
    info = {}
    xmp_bytes = img.info.get('xmp')
    xmp_text = img.info.get('XML:com.adobe.xmp')
    if not xmp_text and xmp_bytes:
        try:
            xmp_text = xmp_bytes.decode('utf-8', errors='ignore')
        except Exception:
            xmp_text = None
    if not xmp_text:
        return [], info

    flags = []
    match = re.search(r'<xmp:CreatorTool>(.*?)</xmp:CreatorTool>', xmp_text, re.DOTALL)
    creator_tool = match.group(1).strip() if match else None
    if creator_tool:
        info['xmp_creator_tool'] = creator_tool[:200]
        if any(marker in creator_tool.lower() for marker in EDITING_SOFTWARE_MARKERS):
            flags.append(
                f"XMP CreatorTool metadata names a design/editing tool ('{creator_tool[:120]}') "
                f"-- this file was composed and exported by that tool, not a direct camera/screenshot capture")
    return flags, info


def _check_exif_consistency(img):
    """Returns (flags, info). Missing EXIF is reported as info only, never
    scored -- screenshots and most messaging-app images never carry EXIF
    at all, so its mere absence is not itself suspicious."""
    info = {'has_exif': False}
    try:
        exif = img.getexif()
    except Exception:
        exif = None
    if not exif:
        return [], info

    from PIL.ExifTags import TAGS
    tags = {}
    for tag_id, value in exif.items():
        if isinstance(value, (bytes, bytearray)):
            continue  # skip binary blobs (e.g. embedded thumbnails/maker notes)
        tags[str(TAGS.get(tag_id, tag_id))] = value

    info['has_exif'] = True
    flags = []

    software = str(tags.get('Software', ''))
    if software:
        info['software'] = software
        if any(marker in software.lower() for marker in EDITING_SOFTWARE_MARKERS):
            flags.append(
                f"EXIF Software tag names an image editor ('{software}') -- "
                f"file was opened and re-saved by editing software")

    created = tags.get('DateTimeOriginal')
    modified = tags.get('DateTime')
    if created and modified and str(created) != str(modified):
        info['datetime_original'] = str(created)
        info['datetime_modified'] = str(modified)
        flags.append(
            f"EXIF modify timestamp ({modified}) differs from the original capture "
            f"timestamp ({created}) -- file was re-saved after it was created")

    return flags, info


def _error_level_analysis(img):
    """Returns (flags, info, preview_base64_png_or_None)."""
    from PIL import Image, ImageChops

    fmt = (img.format or '').upper()
    if fmt not in ('JPEG', 'JPG'):
        return [], {
            'applicable': False,
            'skipped_reason': f"ELA only applies to JPEG images; this file is {img.format or 'an unrecognized format'}.",
        }, None

    rgb = img.convert('RGB')
    buf = io.BytesIO()
    rgb.save(buf, 'JPEG', quality=ELA_JPEG_QUALITY)
    buf.seek(0)
    resaved = Image.open(buf)

    diff = ImageChops.difference(rgb, resaved)
    hist = diff.histogram()  # 768 values: 256 for R, 256 for G, 256 for B
    channel_means = [_channel_mean(hist[i * 256:(i + 1) * 256]) for i in range(3)]
    mean_err = sum(channel_means) / 3.0
    max_err = max(ch[1] for ch in diff.getextrema())  # per-channel (min, max) -> overall max

    ratio = max_err / max(mean_err, ELA_MIN_MEAN_FOR_RATIO)
    anomaly_detected = ratio >= ELA_ANOMALY_RATIO_THRESHOLD and mean_err < ELA_ANOMALY_MEAN_CEILING

    flags = []
    if anomaly_detected:
        flags.append(
            f"Error Level Analysis found a localized region with error level "
            f"~{ratio:.1f}x the image's average -- consistent with a pasted-in "
            f"or differently-compressed region (possible splice/edit, not proof of one)")

    # Amplify the diff into a human-viewable heatmap so an analyst (or the
    # forensic PDF report) can actually see where the anomaly is, not just
    # read a ratio.
    scale = 255.0 / max(max_err, 1.0)
    amplified = diff.point(lambda p: min(255, int(p * scale)))
    preview_buf = io.BytesIO()
    amplified.save(preview_buf, 'PNG')
    preview_b64 = base64.b64encode(preview_buf.getvalue()).decode('ascii')

    info = {
        'applicable': True,
        'mean_error_level': round(mean_err, 2),
        'max_error_level': round(max_err, 2),
        'anomaly_ratio': round(ratio, 2),
        'anomaly_detected': anomaly_detected,
        'jpeg_resave_quality': ELA_JPEG_QUALITY,
    }
    return flags, info, preview_b64


def analyze_image(payload, filename):
    """
    payload: raw attachment bytes (may be None/empty).
    filename: original attachment filename, used only for error messages.

    Returns a dict:
      {'analyzed': bool, 'format': str|None, 'dimensions': str|None,
       'exif_info': {...} (also carries the XMP CreatorTool check's fields),
       'ela_info': {...}, 'ela_preview_base64': str|None,
       'flags': [human-readable strings], 'risk_score': int (0-32, caller
       clamps into its own overall attachment scale), 'note': str|None}

    'note' is set when the check could not run at all (no Pillow, payload
    missing, file doesn't decode as an image) -- distinct from a normal
    "analyzed successfully, nothing flagged" result.
    """
    result = {
        'analyzed': False, 'format': None, 'dimensions': None,
        'exif_info': {}, 'ela_info': {}, 'ela_preview_base64': None,
        'flags': [], 'risk_score': 0, 'note': None,
    }
    if not payload:
        result['note'] = 'No attachment content available to analyze.'
        return result

    try:
        from PIL import Image
    except ImportError:
        result['note'] = ('Pillow is not installed, so image tampering checks could not run -- '
                           'add Pillow to requirements.txt and reinstall to enable this.')
        return result

    try:
        img = Image.open(io.BytesIO(payload))
        img.load()  # force full decode now, so a truncated/corrupt file fails here, not later
    except Exception as e:
        result['note'] = f'Could not decode "{filename}" as an image: {e}'
        return result

    result['analyzed'] = True
    result['format'] = img.format
    result['dimensions'] = f"{img.width}x{img.height}"

    exif_flags, exif_info = _check_exif_consistency(img)
    xmp_flags, xmp_info = _check_xmp_editor(img)
    result['exif_info'] = {**exif_info, **xmp_info}

    try:
        ela_flags, ela_info, preview_b64 = _error_level_analysis(img)
    except Exception as e:
        ela_flags, ela_info, preview_b64 = [], {'applicable': False, 'note': f'ELA failed: {e}'}, None
    result['ela_info'] = ela_info
    result['ela_preview_base64'] = preview_b64

    score = 0
    # Score each specific check independently (matches attachment_scan.py's
    # additive-per-flag style) rather than a generic "score per flag" loop,
    # so the point value of each signal stays explicit and easy to tune.
    software_flagged = any('editor' in f for f in exif_flags)
    timestamp_flagged = any('differs from the original capture timestamp' in f for f in exif_flags)
    xmp_flagged = bool(xmp_flags)
    if software_flagged:
        score += SOFTWARE_TAG_SCORE
    if timestamp_flagged:
        score += TIMESTAMP_MISMATCH_SCORE
    if xmp_flagged:
        score += XMP_CREATOR_TOOL_SCORE
    if ela_info.get('anomaly_detected'):
        score += ELA_ANOMALY_SCORE

    result['flags'] = exif_flags + xmp_flags + ela_flags
    result['risk_score'] = score
    return result