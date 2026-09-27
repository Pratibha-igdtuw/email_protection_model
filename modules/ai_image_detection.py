"""
Module: AI-generated / synthetic image detection.

Answers a different question than modules/image_forensics.py. That module
asks "was this real photo edited after it was taken?" (ELA + EXIF).
This one asks "does this image show any sign of having been produced by
a generative model in the first place, rather than a camera?" The two
findings are kept in entirely separate fields (ai_generation_score /
likely_ai_generated / this module's own flags list) rather than folded
into image_forensics.py's flags/risk_score, because "AI-generated" and
"a real photo that was Photoshopped" are different investigative
conclusions and conflating them would misrepresent the evidence.

Two signals, of very different reliability -- deliberately weighted
that way, not an oversight:

  1. Generation-metadata / provenance detection (the dominant signal).
     Many AI image tools embed their own provenance directly in the
     file: Stable Diffusion web UIs (Automatic1111, ComfyUI, InvokeAI)
     write a 'parameters' or 'prompt'/'workflow' PNG text chunk holding
     the actual prompt, sampler, steps and model hash; several hosted
     tools (Midjourney, Leonardo.Ai, NightCafe, Adobe Firefly, Bing
     Image Creator, DreamStudio, Playground AI, Ideogram, RunwayML,
     NovelAI) set an EXIF Software/Artist tag or XMP CreatorTool naming
     themselves; and the C2PA / IPTC "Content Credentials" standard
     defines a controlled digitalSourceType vocabulary
     (cv.iptc.org/newscodes/digitalsourcetype) whose values name
     algorithmic/trained-model generation when a tool chooses to embed
     it. When any of these fire, that is the file's own creator
     disclosing what made it -- about as reliable as forensic metadata
     gets, short of verifying a cryptographically signed C2PA manifest,
     which this module does not attempt.
  2. Noise/frequency heuristic (supplementary only, scored far lower).
     A lightweight high-frequency noise-texture check: real camera
     sensor output carries a specific noise floor, and heavily
     synthetic or over-denoised images sometimes measure unusually
     smooth. This is a weak, easily-defeated signal -- recompression,
     resizing, or a photo of a screen all shift it, and modern
     computational-photography noise reduction makes plenty of real
     phone photos measure "smooth" too. It never sets
     likely_ai_generated on its own; it only nudges the score alongside
     an existing metadata hit or is reported as low-confidence context.

As with image_forensics.py: a clean result here is NOT proof an image is
a genuine photograph. AI generators increasingly strip or never write
identifying metadata, and there is no publicly known, dependency-light
heuristic that reliably catches a metadata-scrubbed AI image with no
frequency tell. This module surfaces what it can find; it does not
certify authenticity, and that limitation is returned explicitly in
`note` rather than left implicit.
"""
import io

# Hosted/well-known AI image generation tools that sometimes identify
# themselves in EXIF Software/Artist tags, XMP CreatorTool, or embedded
# text metadata.
AI_TOOL_MARKERS = (
    'midjourney', 'dall-e', 'dall·e', 'openai', 'stable diffusion',
    'stability ai', 'nightcafe', 'leonardo.ai', 'leonardo ai',
    'adobe firefly', 'firefly', 'bing image creator', 'dreamstudio',
    'runwayml', 'playground ai', 'ideogram', 'novelai',
    'automatic1111', 'comfyui', 'invokeai',
)

# PNG text-chunk keys that Stable Diffusion web UIs / node tools
# conventionally use to embed the full generation recipe.
SD_METADATA_KEYS = ('parameters', 'prompt', 'workflow')

# C2PA / IPTC "Digital Source Type" controlled-vocabulary values that
# indicate algorithmic/AI generation (see module docstring for the spec
# reference). Matched as a plain substring against the raw file bytes,
# since Pillow doesn't parse XMP/C2PA structurally and a full XMP parser
# is unnecessary just to catch a known controlled value.
C2PA_AI_SOURCE_TYPES = (
    'trainedalgorithmicmedia', 'compositesynthetic', 'algorithmicmedia',
)

METADATA_SIGNAL_SCORE = 45  # dominant, deliberately -- see module docstring
NOISE_SIGNAL_SCORE = 8      # supplementary only, never sets likely_ai_generated alone


def is_image(filename, content_type):
    """Same cheap pre-check as image_forensics.is_image -- duplicated
    locally rather than imported so this module has no dependency on
    image_forensics.py and can be called independently."""
    ext = ''
    if filename and '.' in filename:
        ext = '.' + filename.rsplit('.', 1)[-1].lower()
    ctype = (content_type or '').lower()
    image_exts = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.webp'}
    return ext in image_exts or ctype.startswith('image/')


def _check_generation_metadata(img, raw_bytes):
    """Returns (flags, info) from EXIF, PNG text chunks, and a raw-byte
    scan for XMP/C2PA source-type declarations."""
    flags = []
    info = {}

    try:
        exif = img.getexif()
    except Exception:
        exif = None
    if exif:
        from PIL.ExifTags import TAGS
        for tag_id, value in exif.items():
            if isinstance(value, (bytes, bytearray)):
                continue
            tag_name = str(TAGS.get(tag_id, tag_id))
            if tag_name in ('Software', 'Artist', 'ImageDescription', 'Copyright'):
                val_str = str(value)
                hit = next((m for m in AI_TOOL_MARKERS if m in val_str.lower()), None)
                if hit:
                    flags.append(f"EXIF '{tag_name}' tag names an AI image generator (\"{val_str}\")")
                    info['matched_tool'] = val_str

    # PNG text chunks -- Stable Diffusion / ComfyUI convention. Pillow
    # exposes these as img.text for PNGs that carry tEXt/iTXt chunks.
    png_text = getattr(img, 'text', None) or {}
    for key in SD_METADATA_KEYS:
        raw_val = png_text.get(key)
        if raw_val:
            snippet = raw_val[:200]
            flags.append(
                f"PNG '{key}' metadata chunk contains AI generation data (prompt/sampler/model "
                f"info written by tools such as Stable Diffusion or ComfyUI): "
                f"\"{snippet}{'...' if len(raw_val) > 200 else ''}\""
            )
            info['generation_metadata_key'] = key

    # Raw-byte scan for XMP/C2PA digitalSourceType + tool-name mentions
    # that structured EXIF parsing above wouldn't catch (embedded in an
    # XMP packet rather than classic EXIF tags).
    try:
        blob = raw_bytes[:200000].decode('latin-1', errors='ignore').lower()
        for source_type in C2PA_AI_SOURCE_TYPES:
            if source_type in blob:
                flags.append(
                    f"Embedded C2PA/XMP metadata declares a digital source type of "
                    f"'{source_type}' (IPTC controlled-vocabulary value indicating "
                    f"AI/algorithmic generation)"
                )
                info['c2pa_source_type'] = source_type
                break
        if 'matched_tool' not in info:
            for marker in AI_TOOL_MARKERS:
                if marker in blob:
                    flags.append(f"Embedded XMP/metadata text references an AI generation tool (\"{marker}\")")
                    info['matched_tool'] = marker
                    break
    except Exception:
        pass

    return flags, info


def _noise_texture_signal(img):
    """Lightweight, numpy-based high-frequency noise estimate. Returns
    (flags, info) -- see module docstring for why this is scored far
    below the metadata check and never sets likely_ai_generated alone."""
    info = {'applicable': False}
    try:
        import numpy as np
    except ImportError:
        info['note'] = 'numpy not installed -- noise-texture heuristic skipped.'
        return [], info

    try:
        gray = img.convert('L')
        # This is a texture statistic, not a pixel-perfect check --
        # capping the analysis size keeps it fast on large uploads.
        gray.thumbnail((512, 512))
        arr = np.asarray(gray, dtype=np.float32)
        if arr.size < 64 * 64:
            info['note'] = 'Image too small for a meaningful noise-texture estimate.'
            return [], info

        # 3x3 box-blur via direct convolution (avoids a scipy dependency
        # for something this simple), then measure what the blur
        # removed -- the high-frequency residual.
        padded = np.pad(arr, 1, mode='edge')
        blurred = np.zeros_like(arr)
        for i in range(3):
            for j in range(3):
                blurred += padded[i:i + arr.shape[0], j:j + arr.shape[1]]
        blurred /= 9.0
        residual = arr - blurred
        noise_std = float(np.std(residual))

        info['applicable'] = True
        info['noise_std'] = round(noise_std, 3)

        flags = []
        if noise_std < 1.2:
            flags.append(
                f"Unusually smooth high-frequency texture (noise std {noise_std:.2f}) -- a weak, "
                f"non-definitive signal sometimes associated with AI-generated or heavily "
                f"denoised images; also common in ordinary screenshots and "
                f"aggressively-processed phone photos, so this alone proves nothing"
            )
        return flags, info
    except Exception as e:
        info['note'] = f'Noise-texture heuristic failed: {e}'
        return [], info


def analyze_for_ai_generation(payload, filename):
    """
    payload: raw image bytes.
    filename: original filename, used only for error messages.

    Returns:
      {'analyzed': bool, 'flags': [human-readable strings],
       'ai_generation_score': int (0-53), 'likely_ai_generated': bool,
       'metadata_info': {...}, 'noise_info': {...}, 'note': str|None}

    likely_ai_generated is True only when a metadata/provenance signal
    actually fired -- the noise heuristic alone never sets it (see
    module docstring). Deliberately returned as its own field, separate
    from image_forensics.py's tamper flags/risk_score, so a caller never
    accidentally conflates "AI-generated" with "a real photo that was
    edited."
    """
    result = {
        'analyzed': False, 'flags': [], 'ai_generation_score': 0,
        'likely_ai_generated': False, 'metadata_info': {}, 'noise_info': {},
        'note': None,
    }
    if not payload:
        result['note'] = 'No image content available to analyze.'
        return result

    try:
        from PIL import Image
    except ImportError:
        result['note'] = 'Pillow is not installed, so AI-generation checks could not run.'
        return result

    try:
        img = Image.open(io.BytesIO(payload))
        img.load()
    except Exception as e:
        result['note'] = f'Could not decode "{filename}" as an image: {e}'
        return result

    result['analyzed'] = True

    metadata_flags, metadata_info = _check_generation_metadata(img, payload)
    result['metadata_info'] = metadata_info

    try:
        noise_flags, noise_info = _noise_texture_signal(img)
    except Exception as e:
        noise_flags, noise_info = [], {'applicable': False, 'note': f'Noise heuristic errored: {e}'}
    result['noise_info'] = noise_info

    score = 0
    if metadata_flags:
        score += METADATA_SIGNAL_SCORE
        result['likely_ai_generated'] = True
    if noise_flags:
        score += NOISE_SIGNAL_SCORE

    result['flags'] = metadata_flags + noise_flags
    result['ai_generation_score'] = min(score, 100)

    if not result['flags']:
        result['note'] = (
            'No AI-generation metadata or notable texture anomaly found. This does not confirm '
            'the image is a genuine, unedited photograph -- many AI tools strip or never write '
            'identifying metadata in the first place.'
        )

    return result