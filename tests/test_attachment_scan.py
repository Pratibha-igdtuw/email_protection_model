import io

from PIL import Image

from modules import attachment_scan


def _jpeg_bytes(img, quality=90, exif=None):
    buf = io.BytesIO()
    kwargs = {'quality': quality}
    if exif is not None:
        kwargs['exif'] = exif
    img.save(buf, 'JPEG', **kwargs)
    return buf.getvalue()


def _edited_exif_jpeg():
    exif = Image.Exif()
    exif[0x0131] = 'Adobe Photoshop 25.0'
    exif[0x9003] = '2024:01:01 10:00:00'
    exif[0x0132] = '2024:01:05 15:30:00'
    return _jpeg_bytes(Image.new('RGB', (80, 80)), exif=exif.tobytes())


def test_no_attachments():
    result = attachment_scan.analyze_attachments([])
    assert result == {'attachments': [], 'count': 0, 'risk_score': 0, 'flags': []}


def test_dangerous_extension_flagged():
    result = attachment_scan.analyze_attachments([
        {'filename': 'invoice.exe', 'content_type': 'application/octet-stream',
         'size_bytes': 100, 'sha256': 'abc', 'payload': b'x'},
    ])
    assert result['risk_score'] == 15
    assert result['attachments'][0]['is_dangerous_extension'] is True
    assert result['attachments'][0]['is_image'] is False
    assert result['attachments'][0]['image_forensics'] is None


def test_image_attachment_gets_forensics_and_no_payload_leak():
    payload = _edited_exif_jpeg()
    result = attachment_scan.analyze_attachments([
        {'filename': 'photo.jpg', 'content_type': 'image/jpeg',
         'size_bytes': len(payload), 'sha256': 'deadbeef', 'payload': payload},
    ])
    att = result['attachments'][0]
    assert att['is_image'] is True
    assert 'payload' not in att  # raw bytes must never leak into the returned result
    assert att['image_forensics']['analyzed'] is True
    assert any('editor' in f for f in att['risk_flags'])
    assert any('editor' in f for f in result['flags'])
    assert result['risk_score'] > 0


def test_clean_image_attachment_no_flags():
    payload = _jpeg_bytes(Image.new('RGB', (100, 100), color=(50, 60, 70)))
    result = attachment_scan.analyze_attachments([
        {'filename': 'screenshot.jpg', 'content_type': 'image/jpeg',
         'size_bytes': len(payload), 'sha256': 'abc123', 'payload': payload},
    ])
    att = result['attachments'][0]
    assert att['is_image'] is True
    assert att['risk_flags'] == []
    assert result['risk_score'] == 0


def test_non_image_attachment_skips_forensics():
    result = attachment_scan.analyze_attachments([
        {'filename': 'report.pdf', 'content_type': 'application/pdf',
         'size_bytes': 500, 'sha256': 'xyz', 'payload': b'%PDF-1.4 ...'},
    ])
    att = result['attachments'][0]
    assert att['is_image'] is False
    assert att['image_forensics'] is None


def test_worst_score_is_not_summed_across_attachments():
    payload = _edited_exif_jpeg()  # scores 14 on its own (8 + 6)
    result = attachment_scan.analyze_attachments([
        {'filename': 'a.jpg', 'content_type': 'image/jpeg',
         'size_bytes': len(payload), 'sha256': 'a', 'payload': payload},
        {'filename': 'b.jpg', 'content_type': 'image/jpeg',
         'size_bytes': len(payload), 'sha256': 'b', 'payload': payload},
    ])
    # Two flagged images shouldn't double the score -- it's the worst single
    # attachment's score (capped at 15), not a sum across attachments.
    assert result['risk_score'] == 14
