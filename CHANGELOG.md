# Changelog

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