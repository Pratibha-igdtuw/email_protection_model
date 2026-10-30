import io

import pytest
from PIL import Image

from modules import image_forensics


def _jpeg_bytes(img, quality=90, exif=None):
    buf = io.BytesIO()
    kwargs = {'quality': quality}
    if exif is not None:
        kwargs['exif'] = exif
    img.save(buf, 'JPEG', **kwargs)
    return buf.getvalue()


def _plain_jpeg():
    return _jpeg_bytes(Image.new('RGB', (120, 120), color=(120, 140, 160)))


def _textured(seed, size=(800, 600), noise=40):
    """Deterministic photo-like image: gradient + strong texture. Natural
    photos carry fine detail everywhere; flat synthetic fills do not, and
    would not exercise ELA realistically."""
    import random
    rnd = random.Random(seed)
    img = Image.new('RGB', size)
    px = img.load()
    for y in range(size[1]):
        for x in range(size[0]):
            b = int(80 + 90 * x / size[0] + 40 * y / size[1])
            px[x, y] = tuple(max(0, min(255, v + rnd.randint(-noise, noise))) for v in (b, b // 2, 200 - b // 2))
    return img


def _resave(img, quality, times):
    for _ in range(times):
        img = Image.open(io.BytesIO(_jpeg_bytes(img, quality=quality))).convert('RGB')
    return img


def _spliced_jpeg():
    """A photo whose compression history has settled (saved repeatedly at
    one quality), with a region pasted in from a different, never-
    compressed source and the whole thing saved once more -- the pasted
    region carries a different compression history than the rest, which is
    exactly what ELA is meant to surface."""
    base = _resave(_textured(7), 90, 3)
    patch = _textured(99).crop((200, 150, 440, 330))
    base.paste(patch, (300, 250))
    return _jpeg_bytes(base, quality=90)


def _edited_exif_jpeg():
    exif = Image.Exif()
    exif[0x0131] = 'Adobe Photoshop 25.0'       # Software
    exif[0x9003] = '2024:01:01 10:00:00'        # DateTimeOriginal
    exif[0x0132] = '2024:01:05 15:30:00'        # DateTime (modified)
    return _jpeg_bytes(Image.new('RGB', (80, 80)), exif=exif.tobytes())


def _plain_png():
    buf = io.BytesIO()
    Image.new('RGB', (80, 80), color=(10, 20, 30)).save(buf, 'PNG')
    return buf.getvalue()


def test_is_image_by_extension():
    assert image_forensics.is_image('photo.JPG', None) is True
    assert image_forensics.is_image('scan.png', 'application/octet-stream') is True
    assert image_forensics.is_image('invoice.pdf', 'application/pdf') is False


def test_is_image_by_content_type_when_no_extension():
    assert image_forensics.is_image('(unnamed)', 'image/jpeg') is True
    assert image_forensics.is_image('(unnamed)', 'text/plain') is False


def test_analyze_image_no_payload():
    result = image_forensics.analyze_image(None, 'x.jpg')
    assert result['analyzed'] is False
    assert 'No attachment content' in result['note']
    assert result['risk_score'] == 0


def test_analyze_image_corrupt_data():
    result = image_forensics.analyze_image(b'this is not an image', 'fake.jpg')
    assert result['analyzed'] is False
    assert 'Could not decode' in result['note']
    assert result['risk_score'] == 0


def test_analyze_image_clean_jpeg_no_flags():
    result = image_forensics.analyze_image(_plain_jpeg(), 'clean.jpg')
    assert result['analyzed'] is True
    assert result['format'] == 'JPEG'
    assert result['flags'] == []
    assert result['risk_score'] == 0
    assert result['ela_info']['applicable'] is True
    assert result['ela_info']['anomaly_detected'] is False


def test_analyze_image_spliced_jpeg_flagged_by_ela():
    result = image_forensics.analyze_image(_spliced_jpeg(), 'spliced.jpg')
    assert result['analyzed'] is True
    assert result['ela_info']['anomaly_detected'] is True
    assert any('Error Level Analysis' in f for f in result['flags'])
    assert result['risk_score'] >= image_forensics.ELA_ANOMALY_SCORE
    # A human-viewable heatmap should be produced whenever ELA actually ran.
    assert result['ela_preview_base64']


def test_analyze_image_editing_software_and_timestamp_mismatch_flagged():
    result = image_forensics.analyze_image(_edited_exif_jpeg(), 'edited.jpg')
    assert any('editor' in f for f in result['flags'])
    assert any('differs from the original capture timestamp' in f for f in result['flags'])
    assert result['risk_score'] == (
        image_forensics.SOFTWARE_TAG_SCORE + image_forensics.TIMESTAMP_MISMATCH_SCORE
    )


def test_analyze_image_png_skips_ela_but_still_analyzes():
    result = image_forensics.analyze_image(_plain_png(), 'screenshot.png')
    assert result['analyzed'] is True
    assert result['format'] == 'PNG'
    assert result['ela_info']['applicable'] is False
    assert result['ela_preview_base64'] is None
    # No EXIF at all is expected (and not itself flagged) for a plain PNG.
    assert result['exif_info']['has_exif'] is False
    assert result['flags'] == []


def test_analyze_image_missing_pillow_degrades_gracefully(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == 'PIL':
            raise ImportError('simulated missing Pillow')
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', fake_import)
    result = image_forensics.analyze_image(_plain_jpeg(), 'clean.jpg')
    assert result['analyzed'] is False
    assert 'Pillow is not installed' in result['note']


# --- ELA false-positive regression ------------------------------------------
# Real incident: the ELA check compared the single hottest pixel against the
# mean and flagged every ordinary photo (measured 13-19x on untouched phone
# photos). It now needs one solid cluster of high-error blocks.

def test_untouched_textured_photo_is_not_flagged_by_ela():
    result = image_forensics.analyze_image(_jpeg_bytes(_textured(7), quality=85), 'photo.jpg')
    assert result['analyzed'] is True
    assert result['ela_info']['anomaly_detected'] is False
    assert result['flags'] == []
    assert result['risk_score'] == 0


def test_sharp_edges_alone_do_not_trigger_ela():
    """Rectangles / text-like edges give a few very hot pixels (the old
    max-vs-mean rule fired on this) but no solid pasted-in region."""
    import random
    from PIL import ImageDraw
    rnd = random.Random(3)
    img = _textured(11, noise=6)
    d = ImageDraw.Draw(img)
    for _ in range(60):
        x, y = rnd.randint(0, 740), rnd.randint(0, 540)
        d.rectangle([x, y, x + rnd.randint(8, 50), y + rnd.randint(8, 50)], outline=(rnd.randint(0, 255),) * 3, width=2)
    result = image_forensics.analyze_image(_jpeg_bytes(img, quality=85), 'edges.jpg')
    assert result['ela_info']['anomaly_detected'] is False


# --- editor signatures outside the EXIF Software tag ---------------------------

def _jpeg_with_comment(comment):
    buf = io.BytesIO()
    _textured(5, size=(160, 120), noise=10).save(buf, 'JPEG', quality=90, comment=comment)
    return buf.getvalue()


def test_editor_named_in_jpeg_comment_is_flagged():
    result = image_forensics.analyze_image(_jpeg_with_comment(b'Edited with Photopea'), 'e.jpg')
    assert any('names an image editor' in f for f in result['flags'])
    assert result['risk_score'] >= image_forensics.SOFTWARE_TAG_SCORE


def test_editor_word_inside_pixel_data_is_not_matched():
    clean = _jpeg_bytes(_textured(5, size=(160, 120), noise=10), quality=90)
    result = image_forensics.analyze_image(clean + b'gimp photopea canva' * 3, 'trailing.jpg')
    assert not any('names an image editor' in f for f in result['flags'])


def test_png_text_chunk_editor_is_flagged():
    from PIL.PngImagePlugin import PngInfo
    info = PngInfo()
    info.add_text('Software', 'GIMP 2.10')
    buf = io.BytesIO()
    Image.new('RGB', (40, 40), (1, 2, 3)).save(buf, 'PNG', pnginfo=info)
    result = image_forensics.analyze_image(buf.getvalue(), 'e.png')
    assert any('editor' in f for f in result['flags'])


def test_jpeg_without_exif_gets_an_honest_limits_note():
    result = image_forensics.analyze_image(_jpeg_bytes(_textured(5, size=(160, 120), noise=10), quality=90), 'shot.jpg')
    assert result['notes'] and 'no camera metadata' in result['notes'][0]
    assert result['risk_score'] == 0     # informational only, never scored
