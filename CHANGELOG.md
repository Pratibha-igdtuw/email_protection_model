# Changelog

## Unreleased — A2 UI refresh

**Changed:** full visual refresh ("A2": clean light, orange accent). Design
tokens re-pointed in `static/css/style.css` so every page inherits the new
look; top navbar replaced by a left sidebar (off-canvas on mobile); brand
name unchanged (FORENSIQ). Risk score is now a conic-gradient ring gauge.
Wide data tables no longer collapse (the key-value table rule is scoped away
from tables with a header row).

**Added:** `static/js/forensiq-ui.js` -- animated risk gauge and count-ups,
and an "Analyzing" overlay (scanning card, 6 steps, timer) shown while
`/analyze` runs. Step progress is a fixed-schedule visual cue, not live
backend status. Respects `prefers-reduced-motion`. No new CDN assets, so the
CSP is unchanged.

**Added (accuracy techniques):**
- *Check Image*: C2PA/Content Credentials verification (broken signature = edited after signing; declared AI origin), optional reverse image search (Google Vision) and AI-image detector (Sightengine). New `modules/image_provenance.py`. A clean result is worded "No editing signals found", not "authentic".
- *Verify Website*: optional Google Safe Browsing + VirusTotal (blacklist hit => DANGEROUS), Wikidata official-site lookup for brands not in the curated list, lexical/domain-age signals. New `modules/url_reputation.py`. Unknown brands are no longer guessed from search results.
- *Check Number*: libphonenumber structural profile (type/carrier/region/premium/VoIP/foreign), optional Veriphone live line type (free tier), and a "what did the caller say?" scam-script analyzer (English/Hinglish: OTP, remote-access apps, digital arrest, KYC/SIM-block threats). New `modules/phone_intel.py`, `modules/scam_script.py`. Default region via `DEFAULT_PHONE_REGION` (IN).
- New tests: `tests/test_accuracy_checks.py` (network fully mocked).

**Fixed (wrong analysis):**
- *Check an Image* flagged almost every untouched photo/screenshot as "possible splice/edit": ELA compared the single hottest pixel to the mean (measured 13-19x on real phone photos). It now needs one solid cluster of high-error blocks; tested on real photos (0/7 false flags) and on synthetic splices. Small edits (<~1% of the frame) can be missed -- ELA is a heuristic, not proof either way.
- *Verify a Website* trusted the top web-search results as "official", so `google.com` appeared as WhatsApp's official site, and it displayed only the registrable domain (`delt.whatsapp.com` shown as `whatsapp.com`). Now: curated official domains for common brands, search results kept only if they look like the brand's own site, full address shown, copycat/shared-hosting/non-existent-address detection. New `tests/test_site_verification.py`.

**Fixed (second pass, after re-testing):**
- *Verify a Website*: a sub-address under an official domain (e.g. `delt.whatsapp.com`) is no longer passed as official unless DNS positively confirms it exists (and the domain has no wildcard DNS). Brands in the curated list no longer take any search results; for other brands, lookalike names (`foobank-login-help.com`) are rejected from search hits.
- *Check an Image*: ELA alone cannot see careful edits that were re-saved (measured: edits pasted into real phone photos and re-saved at q95 left no ELA signal at any block size), so detection now also reads editor names from the whole metadata header (JPEG comment, XMP history, Photoshop blocks, PNG text; Photopea, Pixlr, Fotor, Meitu, etc.). The green "clean" badge no longer implies the image is genuine, and a note explains when camera metadata is missing.

**Fixed:** restored the earlier latency budget (GeoIP/AbuseIPDB/DMARC 2s,
relay-trust pool 16); updated a stale signup-redirect test.

## Unreleased — phone/caller check + voice accessibility layer

**Added:** `/check-number` — a phone/caller reputation check ("is this call
genuine?") answering the parallel question to email analysis, since the
platform was email-only before this. Reuses the existing `BlacklistEntry`
table (`indicator_type='phone'`, no migration needed since the column is
already a generic string) plus a new bundled community-reported
scam-number snapshot (`ml_model/scam_numbers.csv`) and an optional live
lookup (`IPQUALITYSCORE_API_KEY`) — same three-tier optional-external-API
pattern as `modules/blacklist.py` uses for IP/domain reputation. New
`modules/phone_reputation.py`, `templates/phone_check.html`, nav entry.

**Added:** a small voice accessibility layer (`static/js/voice.js`) on top
of the browser's built-in Web Speech API — "read result aloud" on both the
new phone-check page and the existing email `result.html`, and a "speak
instead of typing" mic button for entering a phone number. No server
round-trip and no new API key; progressively enhances and hides itself if
the browser lacks the relevant API. Aimed at users (e.g. elderly users)
who find listening/speaking easier than reading/typing a risk verdict.

## Unreleased — analyze-latency pass

## Unreleased — analyze-latency pass

**Follow-up:** raised `WHOIS_TIMEOUT_SECONDS` from 2 back up to 4 after
user feedback that domain-age data was showing "unavailable" too often.
2s was cutting off *genuinely succeeding* WHOIS lookups mid-flight, not
just slow/unresponsive ones — thin-registry TLDs (`.com`/`.net`) legitimately
need a 2-hop referral (TLD registry -> registrar's own server), and that
second hop commonly takes 1.5-3s on its own with nothing wrong. Kept the
other three (GeoIP/AbuseIPDB/DMARC-DNS) at 2s since they're single-request
lookups with no referral chain and don't need the extra room. Re-measured
worst-case end-to-end `/analyze` (network fully blocked, so every call
times out) at 4.1-4.5s — still under the 5s target but with less margin,
so WHOIS is now the first thing to revisit if more headroom is needed
later. Updated `test_analyze_pipeline_timeouts_stay_within_5s_budget`
(renamed from the tighter `..._stay_tight`) to check the actual design
invariant — the *largest single* timeout stays under budget, since the
calls run concurrently — rather than pinning every value equally tight,
which would have fought this deliberate change.

**Problem:** `/analyze` was taking ~18s in production, reported by the user.

**Root cause (found by profiling each pipeline stage individually against
a real sample email):** the pipeline's network-bound calls
(`auth_check`, GeoIP, WHOIS, AbuseIPDB, per-hop relay-trust geolocation)
already ran concurrently via a `ThreadPoolExecutor` — a prior pass had
fixed the sum-of-calls problem. But each call's individual timeout was
generous (WHOIS 6s, GeoIP/AbuseIPDB 4s, DMARC DNS 3s), and since the whole
concurrent block's wall-clock time is bounded by whichever call is
*slowest*, WHOIS alone could account for 6 of the 18s on its own whenever
a registrar was slow to respond, with GeoIP/relay-trust batches adding
more on top when unlucky.

**Fix:** tightened every external-call timeout so the theoretical
worst case (every single call timing out) lands around 2-3s instead of
6+:
- `modules/whois_lookup.py`: `WHOIS_TIMEOUT_SECONDS` 6 → 2
- `modules/geoip.py`: `lookup_ip` default timeout 4 → 2
- `modules/blacklist.py`: `check_abuseipdb` default timeout 4 → 2
- `modules/auth_check.py`: live DMARC DNS lookup `lifetime` 3 → 2
- `modules/relay_trust.py`: per-hop GeoIP thread pool cap 8 → 16 workers,
  so an email with a long Received-header chain (>8 hops) doesn't need a
  second full-timeout batch on top of the first

**Verified:**
- Profiled every pipeline stage individually (parse, auth_check, geoip,
  whois, abuseipdb, relay_trust, classify, attachment/url scan, risk
  score, chain-of-custody + mining + chain verification, PDF report
  generation) before and after — WHOIS dropped from 6.001s to 2.001s per
  call; everything else was already well under 100ms except the
  classifier's one-time model load (~300-500ms on the *first* call in a
  process, ~65ms on every call after — not a per-request cost in a
  running server).
- Measured 3 real end-to-end `/analyze` requests through the actual Flask
  test client (not a synthetic benchmark) in a network-blocked
  environment — i.e. the worst case where WHOIS/GeoIP/AbuseIPDB never
  succeed and always hit their full timeout: 2.51s, 2.13s, 2.11s. Real
  deployments with working outbound network should typically be faster
  than this, since most calls succeed well under their timeout rather
  than always hitting it.
- Full test suite (which exercises `/analyze` through real routes) itself
  dropped from ~15s to ~7s wall-clock, corroborating the fix independent
  of the manual timing script.
- Documented the new timeouts and the concurrency design in README under
  "Analyze latency," including the trade-off (domain-age data goes
  missing more often on a slow WHOIS server in exchange for a hard
  latency ceiling).

## Unreleased — security/ops hardening pass

**Fixes**
- **CSP broke the whole UI on Render.** The `_CSP` header added in the
  earlier pass locked `style-src`/`script-src` to `'self'` without
  checking what the templates actually load. They pull Bootstrap, Font
  Awesome, and Leaflet CSS/JS from `cdnjs.cloudflare.com` and fonts from
  `fonts.googleapis.com`/`fonts.gstatic.com`, and already had inline
  `<script>` blocks (`login.html`, `blockchain.html`, `map.html`) and
  inline event handlers (`dashboard.html`, plus the two new pages this
  session added). A CSP violation doesn't throw an error anywhere visible
  server-side — the browser just silently drops the blocked CSS/JS, which
  looked exactly like "the whole layout is broken" with nothing
  informative in the logs. Fixed by allow-listing the actual CDN/font
  domains and keeping `'unsafe-inline'` on `script-src` (matching what
  `style-src` already had) rather than refactoring every inline handler
  under time pressure while the live site was broken. Added
  `test_csp_allows_every_external_asset_domain_actually_used_by_templates`,
  which scans every template for the external domains it references and
  fails if the CSP doesn't cover one — verified it actually fails against
  the original broken CSP before confirming the fix passes it.
- `tests/test_risk_score.py::test_breakdown_keys_present` was failing
  against current code — the risk breakdown gained `attachment_risk` and
  `url_risk` keys that the test's expected set never included. Updated the
  test and added dedicated coverage for both fields (cap behavior, default
  to zero when omitted).
- README's risk-weighting table didn't mention `attachment_risk` /
  `url_risk` at all, even though `modules/risk_score.py` scores them — the
  table now matches the code.
- `tests/conftest.py`'s `app` fixture kept one ambient `app_context()` open
  across every `client.get()`/`client.post()` call in a test. Flask reuses
  an already-active app context instead of pushing a fresh one per call, so
  Flask-Login's per-app-context user cache (`g._login_user`) was bleeding
  across what should have been independent requests within a single test —
  invisible until a test needed `current_user` freshly re-resolved mid-test
  (exactly what the new API-key tests below need). Real HTTP requests don't
  share an ambient app context, so this was purely a test-isolation gap,
  not a production bug — but it could have hidden real ones. Fixed by only
  holding the app context around table create/drop, not around the yield.

**Added**
- **API keys** (`models.User.api_key_hash/_prefix/_created_at`,
  `/account/api-key`): each account can generate one personal key (salted
  hash at rest, shown once) to call `/api/cases` without a browser session.
  Implemented via Flask-Login's `request_loader`, scoped to a narrow
  allow-list (`API_KEY_ELIGIBLE_ENDPOINTS`) so a leaked key only ever
  reaches read-oriented API surfaces — not the interactive app. No session
  cookie is set for key-authenticated requests.
- **Audit trail** (`models.AuditLog`, `/admin/audit-log`, admin-only):
  append-only log of signup, login (success/failed/locked-out), logout,
  case analysis, verdict changes, CSV export, model retraining, and API key
  issuance/use/revocation. Distinct from the existing blockchain evidence
  ledger, which attests to *case* integrity, not *user activity*.
- **Security response headers** (`app.py::_set_security_headers`): CSP,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy`, `Permissions-Policy`, and HSTS once
  `APP_ENV=production`. Previously none were set.
- **Migration**: `migrations/versions/7a135d5b9d51_*.py` (generated via
  `flask db migrate`, matching the project's own documented workflow) for
  the new `audit_log` table and `users` columns.
- **CI**: a `dependency-audit` job runs `pip-audit` against
  `requirements.txt` on every push/PR (non-blocking for now — see the
  workflow file for why).
- **Docker**: `Dockerfile` + `docker-compose.yml` running gunicorn behind
  Redis-backed rate limiting by default, so the "each worker keeps its own
  counters" gotcha documented under "Rate limiting in production" doesn't
  bite by default in a multi-worker deployment.
- **`flask create-admin <email>`** CLI command: promotes an existing
  account to admin, or creates a new admin account (prompting securely for
  name/password if not passed as flags) if the email doesn't exist yet.
  There's still no seeded admin (or any seeded user) — this is the
  supported way to get the first one, instead of hand-editing the DB.
- Tests: `tests/test_api_key_and_audit.py` (API key full flow including
  revocation and scope restriction, security headers present, audit
  entries recorded, `create-admin` create/promote/weak-password-rejected
  paths).

**Verified**
- Full suite: 52 passed, 1 pre-existing skip (`test_blockchain_anchor.py`,
  needs the optional `eth-tester`/`py-evm` packages), 0 failures.
- Manually walked the API-key flow end-to-end against the real routes
  (generate → analyze → logout → call `/api/cases` with the key → confirm
  a non-eligible route rejects the same key → revoke → confirm it stops
  working).

**Known limitations / not done in this pass**
- `Dockerfile`/`docker-compose.yml` were written and YAML-validated but not
  build-tested (no Docker daemon in the environment they were written in)
  — worth a real `docker compose up` smoke test before relying on it.
- `app.py` is still one ~1000-line file; splitting it into blueprints would
  help long-term maintainability but wasn't attempted here, to keep this
  pass's diff reviewable and low-risk.
- The ML classifier is unchanged (still TF-IDF + Naive Bayes) — upgrading
  or ensembling it is a separate, larger effort involving real model
  comparison against held-out data, not attempted here.