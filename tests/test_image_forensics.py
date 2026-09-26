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


def _spliced_jpeg():
    """A base image re-compressed at one quality with a patch pasted in
    that was independently compressed at a very different quality --
    simulates a region with a different compression history, which is
    exactly what ELA is meant to surface."""
    base = Image.new('RGB', (200, 200), color=(120, 140, 160))
    base = Image.open(io.BytesIO(_jpeg_bytes(base, quality=95))).convert('RGB')

    patch = Image.new('RGB', (60, 60), color=(200, 50, 50))
    patch = Image.open(io.BytesIO(_jpeg_bytes(patch, quality=20))).convert('RGB')

    base.paste(patch, (70, 70))
    return _jpeg_bytes(base, quality=95)


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
