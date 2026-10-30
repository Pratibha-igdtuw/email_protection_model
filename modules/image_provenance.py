"""
Image provenance and external verification -- the checks that can actually
settle "is this image what it claims to be?", unlike pixel heuristics (ELA)
which can only hint.

Three independent sources, each optional and failing soft:

  1. C2PA Content Credentials (no key, runs locally via `c2pa-python`).
     If the image carries a signed manifest, this reads who made it, with
     what tool, whether it was AI-generated, what edits were declared, and
     -- most importantly -- whether the signature still validates. A
     manifest that no longer validates means the file was changed after it
     was signed. Only images that were signed at creation have this (it is
     rare, and social apps often strip it), so "no manifest" is neutral,
     never evidence either way.
  2. Reverse image search (Google Cloud Vision Web Detection;
     GOOGLE_VISION_API_KEY). Finds other pages where the same or a very
     similar image already appears -- the standard check for recycled or
     stolen photos and "old photo, new caption" misinformation.
  3. Trained AI-image detector (Sightengine; SIGHTENGINE_API_USER +
     SIGHTENGINE_API_SECRET). A model looking at the pixels, so it works
     when metadata has been stripped, unlike the metadata-only check in
     ai_image_detection.py. A probability, not a proof.

Each function returns a dict whose 'status' is one of:
  'success' / 'not_found' (C2PA only) / 'not_configured' / 'unavailable'
"""
import base64
import io
import json
import os

import requests

VISION_URL = "https://vision.googleapis.com/v1/images:annotate"
SIGHTENGINE_URL = "https://api.sightengine.com/1.0/check.json"
DEFAULT_TIMEOUT = 6

_AI_SOURCE_TYPES = ('trainedalgorithmicmedia', 'compositewithtrainedalgorithmicmedia', 'algorithmicmedia')


# --------------------------------------------------------------------------
# 1. C2PA Content Credentials
# --------------------------------------------------------------------------
def parse_manifest_store(store):
    """Turns a c2pa manifest-store dict (as produced by the C2PA reader's
    .json()) into a small, plain summary. Pure function, so it is testable
    without a signed sample image."""
    manifests = (store or {}).get('manifests') or {}
    active = manifests.get((store or {}).get('active_manifest')) or (next(iter(manifests.values()), {}) if manifests else {})

    generator = active.get('claim_generator')
    for info in active.get('claim_generator_info') or []:
        if info.get('name'):
            generator = info['name'] + (f" {info['version']}" if info.get('version') else '')
            break

    actions, ai_generated = [], False
    for assertion in active.get('assertions') or []:
        if str(assertion.get('label', '')).startswith('c2pa.actions'):
            for act in (assertion.get('data') or {}).get('actions') or []:
                name = act.get('action')
                if name and name not in actions:
                    actions.append(name)
                src = str(act.get('digitalSourceType', '')).lower().rsplit('/', 1)[-1]
                if src in _AI_SOURCE_TYPES:
                    ai_generated = True

    sig = active.get('signature_info') or {}
    failures = [v for v in (store.get('validation_status') or [])
                if 'success' not in str(v.get('code', '')).lower()]
    state = str(store.get('validation_state', '')).lower()
    valid = not failures and state != 'invalid'

    return {
        'has_manifest': bool(active),
        'valid': valid,
        'trusted': state == 'trusted',
        'issuer': sig.get('issuer'),
        'signed_at': sig.get('time'),
        'claim_generator': generator,
        'title': active.get('title'),
        'actions': actions[:12],
        'ai_generated': ai_generated,
        'validation_failures': [str(f.get('code')) for f in failures][:6],
    }


def check_c2pa(payload, filename='image'):
    """Read and validate C2PA Content Credentials embedded in the image."""
    try:
        import c2pa
    except ImportError:
        return {'status': 'not_configured', 'message': 'c2pa-python is not installed.'}

    ext = os.path.splitext(filename or '')[1].lower().lstrip('.')
    mime = {'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png', 'webp': 'image/webp',
            'gif': 'image/gif', 'tif': 'image/tiff', 'tiff': 'image/tiff'}.get(ext, 'image/jpeg')
    try:
        reader = c2pa.Reader(mime, io.BytesIO(payload))
    except Exception as e:                       # no manifest, or unsupported container
        if 'ManifestNotFound' in str(e) or 'no JUMBF' in str(e) or 'not found' in str(e).lower():
            return {'status': 'not_found'}
        return {'status': 'unavailable', 'message': str(e)[:200]}
    try:
        summary = parse_manifest_store(json.loads(reader.json()))
    except Exception as e:
        return {'status': 'unavailable', 'message': f'Could not read manifest: {e}'[:200]}
    finally:
        try:
            reader.close()
        except Exception:
            pass
    summary['status'] = 'success'
    return summary


# --------------------------------------------------------------------------
# 2. Reverse image search (Google Cloud Vision Web Detection)
# --------------------------------------------------------------------------
def reverse_image_search(payload, timeout=DEFAULT_TIMEOUT):
    api_key = os.environ.get('GOOGLE_VISION_API_KEY')
    if not api_key:
        return {'status': 'not_configured',
                'message': 'Set GOOGLE_VISION_API_KEY to enable reverse image search.'}
    try:
        resp = requests.post(
            VISION_URL, params={'key': api_key}, timeout=timeout,
            json={'requests': [{
                'image': {'content': base64.b64encode(payload).decode('ascii')},
                'features': [{'type': 'WEB_DETECTION', 'maxResults': 10}],
            }]},
        )
        resp.raise_for_status()
        first = (resp.json().get('responses') or [{}])[0]
        if first.get('error'):
            return {'status': 'unavailable', 'message': str(first['error'].get('message', ''))[:200]}
        web = first.get('webDetection') or {}
        pages = [{'url': p.get('url'), 'title': p.get('pageTitle')}
                 for p in (web.get('pagesWithMatchingImages') or [])[:6] if p.get('url')]
        return {
            'status': 'success',
            'exact_matches': len(web.get('fullMatchingImages') or []),
            'similar_matches': len(web.get('partialMatchingImages') or []) + len(web.get('visuallySimilarImages') or []),
            'pages': pages,
            'best_guess': ((web.get('bestGuessLabels') or [{}])[0]).get('label'),
            'entities': [e.get('description') for e in (web.get('webEntities') or [])[:5] if e.get('description')],
        }
    except requests.exceptions.RequestException as e:
        return {'status': 'unavailable', 'message': str(e)[:200]}
    except (ValueError, KeyError, IndexError) as e:
        return {'status': 'unavailable', 'message': f'Unexpected response: {e}'}


# --------------------------------------------------------------------------
# 3. Trained AI-image detector (Sightengine)
# --------------------------------------------------------------------------
def ai_detector(payload, filename='image', timeout=DEFAULT_TIMEOUT):
    user, secret = os.environ.get('SIGHTENGINE_API_USER'), os.environ.get('SIGHTENGINE_API_SECRET')
    if not user or not secret:
        return {'status': 'not_configured',
                'message': 'Set SIGHTENGINE_API_USER and SIGHTENGINE_API_SECRET to enable the trained AI-image detector.'}
    try:
        resp = requests.post(
            SIGHTENGINE_URL, timeout=timeout,
            data={'models': 'genai', 'api_user': user, 'api_secret': secret},
            files={'media': (filename or 'image', payload)},
        )
        data = resp.json()
        if data.get('status') != 'success':
            return {'status': 'unavailable', 'message': str((data.get('error') or {}).get('message', 'request failed'))[:200]}
        prob = float((data.get('type') or {}).get('ai_generated', 0))
        return {
            'status': 'success',
            'ai_probability': round(prob, 3),
            'label': 'likely AI-generated' if prob >= 0.8 else ('possibly AI-generated' if prob >= 0.5 else 'likely not AI-generated'),
        }
    except requests.exceptions.RequestException as e:
        return {'status': 'unavailable', 'message': str(e)[:200]}
    except (ValueError, TypeError) as e:
        return {'status': 'unavailable', 'message': f'Unexpected response: {e}'}


def verify_image(payload, filename='image'):
    """Run all three checks concurrently; never raises."""
    import concurrent.futures
    jobs = {
        'c2pa': (check_c2pa, (payload, filename)),
        'reverse_search': (reverse_image_search, (payload,)),
        'ai_detector': (ai_detector, (payload, filename)),
    }
    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = {k: pool.submit(fn, *args) for k, (fn, args) in jobs.items()}
        for k, fut in futures.items():
            try:
                out[k] = fut.result(timeout=DEFAULT_TIMEOUT + 2)
            except Exception as e:
                out[k] = {'status': 'unavailable', 'message': str(e)[:200]}
    return out


def summarize(provenance):
    """Plain-language findings (list of dicts: level 'bad'/'warn'/'info'/'ok',
    text) from verify_image() output, for the UI and the evidence record."""
    findings = []
    c = provenance.get('c2pa') or {}
    if c.get('status') == 'success':
        who = c.get('claim_generator') or 'unknown tool'
        if not c.get('valid'):
            findings.append({'level': 'bad', 'text': f"Signed Content Credentials were found (made with {who}) but the "
                             "signature NO LONGER VALIDATES -- the image was changed after it was signed."})
        else:
            findings.append({'level': 'ok', 'text': f"Valid signed Content Credentials: made with {who}"
                             + (f", signed by {c['issuer']}" if c.get('issuer') else '') + '.'})
        if c.get('ai_generated'):
            findings.append({'level': 'bad', 'text': 'The Content Credentials declare this image was AI-generated.'})
        edits = [a for a in c.get('actions', []) if 'edit' in a or 'filter' in a or 'crop' in a or 'placed' in a]
        if edits:
            findings.append({'level': 'warn', 'text': 'Declared edits: ' + ', '.join(edits[:5]) + '.'})
    elif c.get('status') == 'not_found':
        findings.append({'level': 'info', 'text': 'No Content Credentials (C2PA) in this file. This is normal: most images '
                         'are not signed, and sharing apps strip them -- it proves nothing either way.'})

    r = provenance.get('reverse_search') or {}
    if r.get('status') == 'success':
        n = r.get('exact_matches', 0)
        if n or r.get('pages'):
            findings.append({'level': 'warn', 'text': f"This image already appears elsewhere on the web ({n} exact match(es), "
                             f"{len(r.get('pages', []))} page(s) listed). If someone sent it as a new/original photo, check whether "
                             "it was taken from one of those pages."})
        else:
            findings.append({'level': 'info', 'text': 'No other copies of this image were found online.'})

    a = provenance.get('ai_detector') or {}
    if a.get('status') == 'success':
        pct = round(a['ai_probability'] * 100)
        findings.append({'level': 'bad' if a['ai_probability'] >= 0.8 else ('warn' if a['ai_probability'] >= 0.5 else 'ok'),
                         'text': f"AI-image detector: {pct}% probability AI-generated ({a['label']}). A probability, not proof."})
    return findings
