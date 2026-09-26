# FORENSIQ — AI-Powered Digital Forensics Investigation Platform

Collect, analyse, authenticate, and correlate digital evidence from multiple
sources — email, images, PDFs/Word documents, chat and SMS exports, phone
numbers — in one investigation workspace. Every source runs through the
forensic checks appropriate to it (AI/NLP content analysis, sender
authentication, image tamper detection via ELA/EXIF, document tamper
detection, WHOIS/blacklist reputation, geolocation), gets a SHA-256 hash
committed to an append-only blockchain evidence ledger at ingestion, and
feeds a cross-evidence correlation graph that surfaces a shared domain,
IP, sender, or phone number across otherwise-unrelated pieces of
evidence. Each case or evidence item gets an auto-generated narrative
reconstructing what the pipeline found, plus a downloadable PDF forensic
report.

Every one of the platform's cross-source analytical views — content
classification, cluster detection, and anomaly detection — now spans
**both** analyzed-email cases and the generic Evidence ledger, not just
email:

- **AI content analysis**: the trained phishing classifier + NLP
  social-engineering cues (urgency language, suspicious/shortened links)
  run on email *and* on SMS exports/chat logs at ingestion
  (`modules/classifier.py::classify_text_fragment`), producing a
  fraud-likelihood score and flags for evidence types that previously got
  no content analysis at all.
- **Clustering** (`/dashboard/clusters`) and **anomaly detection**
  (`/dashboard/anomalies`) are both built on the same cross-source
  correlation graph / entity-event model as domains, IPs, senders, and
  phone numbers extracted from Evidence items — so a repeat phone number
  across two chat-log uploads, with zero emails involved, can surface a
  cluster or trigger a volume-spike anomaly on its own.
- **Authentication** (hash + blockchain ledger) and **fraud/manipulation
  detection** (ELA/EXIF for images, tamper forensics for documents) were
  already uniform across every evidence type.

Email analysis (SPF/DKIM/DMARC, WHOIS, geolocation, blacklist/PhishTank
reputation, a 0-100 combined risk score) remains the most fully built-out
single evidence type — it's the only type with domain-age/geo/auth
checks, which are inherently email-specific concepts — but it's one
evidence type among several now, not the whole platform. See "Project
structure" below for how the pieces fit together.

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

The ML phishing classifier is already trained and included
(`ml_model/phishing_model.joblib`), trained on `ml_model/training_dataset.csv`
— a cleaned, deduplicated combination of the real **Enron**, **SpamAssassin**,
and **Nazario** email corpora (~15,300 emails, 97% holdout accuracy), not
synthetic examples. See `ml_model/build_training_dataset.py` for exactly how
it was built and how to rebuild it from fresh copies of the source corpora.
To retrain after any change to the dataset:

```bash
python ml_model/train_model.py
```

## Run

```bash
python app.py
```

Visit **http://localhost:5000** — you'll land on the public marketing page.
Create a free account (`/signup`) to reach the actual tool; every case,
dashboard, and ledger view is private to the signed-in account. There's no
seeded demo user, and no seeded admin either — every account signs up as a
regular user by default. To get your first admin (needed for `/admin/audit-log`
and model retraining), run:

```bash
flask create-admin you@example.com
```

This promotes the account if it already exists, or creates a new admin
account (prompting securely for name/password) if it doesn't. Run it in the
same environment as the app (same `DATABASE_URL`) -- e.g.
`docker compose run --rm web flask create-admin you@example.com` if you're
using the Docker setup.

- `/` — public landing page
- `/signup`, `/login`, `/logout` — account creation and session management
- `/overview` — unified cross-source landing dashboard: every analyzed
  email case + every ingested evidence item, severity/type breakdown,
  cluster and anomaly summary, top correlations, and a combined recent
  activity feed, in one screen
- `/evidence/upload` — ingest an SMS export, chat log, image, document
  (PDF/Word), or other file as standalone forensic evidence — auto-hashed,
  metadata-extracted (EXIF + ELA tamper check for images, tamper forensics
  for documents, AI fraud-likelihood scan + phone-number extraction for
  SMS/chat text), and committed to the blockchain ledger like an analyzed
  email. Uploading a raw `.eml` here now runs the *same* full pipeline as
  `/app` (classifier, SPF/DKIM/DMARC, risk score) instead of a generic
  mime/size check — it auto-creates a real Case and links this Evidence
  item to it
- `/evidence`, `/evidence/<evidence_ref>` — evidence list and detail
  (integrity verification, extracted metadata, auto-generated narrative)
- `/dashboard/correlation` — cross-evidence correlation graph spanning
  both analyzed-email cases and the generic evidence ledger; surfaces a
  domain/IP/sender/phone number shared across otherwise-unrelated
  evidence as a visible pivot point
- `/app` — paste raw email source or upload a `.eml` file, run analysis
  (the email-specific evidence path)
- `/connect-mailbox` — Gmail via OAuth2 (if configured, see below) or
  IMAP with an app password for Gmail/Outlook/Exchange
- `/dashboard` — analyzed-email case queue: search, filter by severity,
  export CSV, retrain model (email cases only — see `/overview`,
  `/dashboard/correlation`, `/dashboard/clusters`, and `/dashboard/anomalies`
  above/below for the cross-source views)
- `/dashboard/map` — geolocated email cases on a live map (Evidence items
  have no geolocation data, so this one stays email-specific)
- `/dashboard/clusters` — repeat-offender / coordinated-campaign clustering
  spanning both email cases and Evidence items, built on the same
  correlation graph as `/dashboard/correlation` — a shared domain, IP,
  sender, or phone number across 2+ sources is a cluster, regardless of
  what type those sources are
- `/dashboard/anomalies` — volume/timing anomaly detection spanning both
  email cases (by sender domain/country) and Evidence items (by phone
  number extracted from SMS/chat text) — an entity spiking or appearing at
  an unusual hour can trigger an anomaly even with no case involved at all
- `/case/<case_ref>` — case detail, auto-generated incident narrative,
  incident-reconstruction timeline, analyst notes, feedback verdict buttons
- `/report/<case_ref>` — download the generated PDF forensic report
- `/blockchain` — the append-only evidence hash-chain (spans both cases
  and evidence items), plus each block's public on-chain anchoring status
  (see "Real blockchain anchoring setup" below)
- `/api/cases` — JSON list of your analyzed cases (session login, or an
  `X-API-Key` header — see "API key access" below)
- `/account/api-key` — generate/revoke your personal API key
- `/admin/audit-log` — admin-only activity trail (who signed in, analyzed a
  case, ingested evidence, changed a verdict, exported data, or retrained
  the model)

Two ready-to-use test emails are in `sample_emails/`:
- `phishing_sample.eml` — spoofed PayPal email with SPF/DKIM/DMARC failures,
  a lookalike domain, urgency language, and a shortened link (expect High/Critical).
- `legit_sample.eml` — normal internal email with passing SPF/DKIM/DMARC
  (expect Low score).

## Project structure

```
app.py                    Flask routes, auth (Flask-Login), rate limiting, pipeline orchestration
config.py                  Environment-based config (development/testing/production)
models.py                  SQLAlchemy models (User, Case, BlacklistEntry, ChainBlock, ...)
migrations/                Flask-Migrate/Alembic schema migrations
contracts/
  EvidenceAnchor.sol        On-chain anchoring contract (see "Real blockchain anchoring setup")
  build/                    Checked-in compiled ABI/bytecode (see contracts/README.md)
modules/
  evidence_ingest.py          Multi-source evidence ingestion: SMS export, chat log, image,
                               document, or other file -- hashing, type-appropriate metadata, and
                               (for SMS/chat) an AI fraud-likelihood scan via classifier.py
  image_forensics.py          Image tamper detection: Error Level Analysis (ELA) + EXIF
                               editing-tool/timestamp consistency check
  document_forensics.py       PDF/Word tamper detection: producer/creator metadata, creation vs.
                               modification date, incremental-update count
  correlation_graph.py        Cross-evidence correlation graph spanning both cases and evidence
                               items -- shared sender/domain/IP/phone becomes a visible pivot
  case_narrative.py           Auto-generated plain-English narrative per case/evidence item,
                               compiled from everything else the pipeline already computed
  timeline.py                 Incident-reconstruction timeline (received -> auth failure ->
                               content/attachment/URL flag -> clustered -> hashed) per case
  anomaly.py                  Volume/timing anomaly detection spanning cases (domain/country) and
                               Evidence items (phone numbers from SMS/chat text)
  parser.py                   Module 1: header/body parser, Received chain, IP extraction
  classifier.py                Module 1: ML phishing classifier + NLP social-engineering cues for
                               email; classify_text_fragment() reuses the same model for SMS/chat text
  geoip.py                     Module 2: IP geolocation (ip-api.com) + brand/hosting mismatch
  whois_lookup.py               Module 3: WHOIS domain age check
  auth_check.py                 Module 3: SPF / DKIM / DMARC verification (headers + optional live DNS)
  blacklist.py                  Module 3: local blacklist + PhishTank-verified domain check + optional AbuseIPDB
  clustering.py                 Repeat-offender IP/ASN/domain clustering used only for the
                               /dashboard/map summary; /dashboard/clusters itself is powered by
                               correlation_graph.py, above, so it covers Evidence too
  risk_score.py                 Module 4: combined weighted risk score + severity banding (email cases)
  report_gen.py                 Module 3: PDF forensic report (ReportLab)
  chain_of_custody.py            SHA-256 evidence hashing + custody record (cases and evidence items)
  blockchain.py                  Local append-only hash-chain (mined per case/evidence item)
  blockchain_anchor.py            Real on-chain anchoring via web3.py (optional, see below)
  oauth_gmail.py                  Gmail OAuth2 connector
  mailbox_connector.py            IMAP app-password connector (Gmail/Outlook/Exchange)
  retrain.py                   Self-improving feedback-loop retraining
templates/                  Landing, signup/login, and app UI
static/css/style.css         Design system
ml_model/
  training_dataset.csv         Real Enron + SpamAssassin + Nazario emails (~15,300 rows)
  build_training_dataset.py    Rebuilds training_dataset.csv from the original public sources
  phishtank_domains.csv        Snapshot of PhishTank-verified phishing domains, used by blacklist.py
  refresh_phishtank.py         Refreshes the PhishTank snapshot (also runs on a schedule, see .github/workflows)
  train_model.py               Retrains the Naive Bayes/TF-IDF classifier
  phishing_model.joblib        Pre-trained model (included, ready to use — 97% holdout accuracy)
tests/                      pytest suite (offline/deterministic — external lookups are stubbed)
sample_emails/               Two .eml files for quick testing
case_reports/                 Generated PDF reports + stored raw .eml files (created at runtime)
instance/                    SQLite database (created at runtime)
```

## Notes on external lookups

- **GeoIP** uses ipwho.is's free tier (no key needed). If the runtime
  environment has no outbound internet access, this gracefully falls back to
  a "lookup unavailable" status rather than breaking the pipeline.
- **WHOIS** uses `python-whois`, which queries public WHOIS servers directly —
  same graceful fallback applies if network access is restricted.
- **AbuseIPDB** blacklist check is optional: set the `ABUSEIPDB_API_KEY`
  environment variable to enable it. Without a key it just reports
  `not_configured` and the local blacklist table still works standalone.
- **IPQualityScore** phone reputation check (`/check-number`, `modules/phone_reputation.py`)
  is optional the same way: set `IPQUALITYSCORE_API_KEY` for a live
  carrier/fraud-score lookup. Without a key, the check still runs against
  the local blacklist (`BlacklistEntry` rows with `indicator_type='phone'`)
  and the bundled community-reported scam-number snapshot
  (`ml_model/scam_numbers.csv`).
- **DMARC** policy is read from the `Authentication-Results` header first
  (works fully offline); a live DNS TXT lookup via `dnspython` is attempted
  as a secondary confirmation and silently skipped if unavailable.

### Analyze latency

`/analyze` runs auth check, GeoIP, WHOIS, AbuseIPDB, and the per-hop relay
trust reconstruction concurrently (`app.py::run_pipeline`), so end-to-end
time is roughly the *slowest* of those, not their sum. Each one has its own
hard timeout so a slow/unresponsive external service degrades gracefully
(that signal comes back as "unavailable" and the analysis still completes)
instead of blocking the whole request:

| Call | Timeout |
|---|---|
| WHOIS (`modules/whois_lookup.py`) | 4s |
| GeoIP (`modules/geoip.py`) | 2s |
| AbuseIPDB (`modules/blacklist.py`) | 2s |
| Live DMARC DNS lookup (`modules/auth_check.py`) | 2s |

WHOIS gets more room than the others deliberately: a genuinely successful
lookup on a thin-registry TLD (`.com`/`.net`) legitimately involves a
2-hop referral (TLD registry -> registrar's own WHOIS server), and that
second hop commonly takes 1.5-3s on its own with nothing wrong -- a
tighter cap was turning *working* lookups into "unavailable," not just
filtering out genuinely slow ones. GeoIP/AbuseIPDB/DMARC are all single-
request lookups with no referral chain, so they don't need the extra
room.

Typical end-to-end time is 1-3s; worst case (every external call timing
out, i.e. no outbound network at all) measured ~4.1-4.5s end-to-end
through the real `/analyze` route — still under a 5s target, but WHOIS is
the dominant term now, so it's the first thing to tighten if you need
more headroom back (accepting that domain-age data goes missing more
often as a trade-off).

## Combined risk score weighting

| Component                        | Max points |
|-----------------------------------|-----------|
| ML content phishing probability   | 30 |
| NLP/heuristic red flags            | 20 |
| SPF/DKIM/DMARC authentication      | 30 (highest weight — strongest spoofing signal) |
| Blacklist/reputation                | 20 |
| Attachment risk (dangerous/double-extension/macro files) | 15 |
| URL risk (IP-literal, shortener, punycode, brand impersonation, anchor/href mismatch) | 15 |
| WHOIS newly-registered domain (<30d)| +10 flat |
| GeoIP brand/hosting mismatch        | +10 flat |

Raw component total can exceed 100 (150 at max); the combined score is capped
at 100. Bands: 0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical.

## Database migrations

Dev/test runs auto-create tables from `models.py` (`AUTO_CREATE_TABLES=True`
in `DevelopmentConfig`/`TestingConfig`) so `python app.py` just works with no
extra steps. **Production** (`APP_ENV=production`) disables that and uses
Flask-Migrate/Alembic instead, so schema changes are tracked and reversible:

```bash
export APP_ENV=production
export SECRET_KEY=<a real secret>
export DATABASE_URL=<your production database URL>
flask db upgrade
```

`migrations/versions/` holds the schema history, starting from a migration
that creates the full schema from scratch (including the blockchain
ledger's `chain_blocks` table) — safe to run against a genuinely empty
database. After changing any
model in `models.py`, generate the next migration the normal way:

```bash
flask db migrate -m "describe the change"
flask db upgrade
```

Always read the autogenerated migration before applying it — Alembic
autogenerate is good but not infallible (it won't detect some constraint-only
changes, and SQLite's batch-mode table rebuild for `ALTER` can need a manual
nudge on more complex changes).

## Blockchain evidence ledger

Every analyzed case gets a block in an append-only hash-chain
(`modules/blockchain.py`): each block commits to the previous block's hash
via SHA-256, mined with a small proof-of-work step, so editing any past
block — or the case evidence it attests to — breaks every link after it.
`/blockchain` shows the full ledger and verifies it end-to-end on every
page load. This is a genuine blockchain data structure, but it's a
**single-writer, single-server ledger** — there's no P2P network or
consensus protocol, because its job is detecting undetected tampering
with *this* server's database, not agreeing on shared state across
mutually distrusting parties.

### Real blockchain anchoring setup

To close that gap — so a block's existence at a given time is attested to
by a real public network, not just this server — each block's hash can
also be anchored on a public Ethereum-compatible testnet (Sepolia by
default) via `contracts/EvidenceAnchor.sol`. This is optional and strictly
additive: without it, the local hash-chain above works exactly the same.

**1. Create a testnet-only wallet.** Install [MetaMask](https://metamask.io)
(or any EVM wallet), create a new account, and export its private key
(Account details → Show private key). **Use a wallet that will never hold
real funds** — this key goes in a server env var.

**2. Get free Sepolia testnet ETH.** You need a small amount to pay gas —
it has no real value. Use a faucet such as
[sepoliafaucet.com](https://sepoliafaucet.com) or
[Google's Sepolia faucet](https://cloud.google.com/application/web3/faucet/ethereum/sepolia)
and send it to your new wallet's address.

**3. Get a free Sepolia RPC URL.** Sign up (free tier) at a provider such
as [Alchemy](https://www.alchemy.com) or [Infura](https://infura.io), create
a Sepolia app, and copy its HTTPS endpoint URL.

**4. Deploy `contracts/EvidenceAnchor.sol` via Remix** (no local Solidity
toolchain needed, ~5 minutes):
   - Open [remix.ethereum.org](https://remix.ethereum.org), create a new
     file, paste in `contracts/EvidenceAnchor.sol`.
   - Compile tab → select compiler `0.8.19` → Compile.
   - Deploy tab → environment "Injected Provider - MetaMask" → make sure
     MetaMask is on the Sepolia network → Deploy → confirm in MetaMask.
   - Copy the deployed contract's address from Remix's "Deployed Contracts" panel.
   - (Prefer a script instead of Remix? `contracts/build/` already has the
     compiled ABI/bytecode — see `contracts/README.md`.)

**5. Set these env vars** before running the app:

```bash
export WEB3_RPC_URL="https://eth-sepolia.g.alchemy.com/v2/<your-key>"
export WEB3_PRIVATE_KEY="0x<your-testnet-wallet-private-key>"
export WEB3_CONTRACT_ADDRESS="0x<address-from-step-4>"
# optional, these are already the defaults:
export WEB3_NETWORK_NAME="sepolia"
export WEB3_EXPLORER_BASE_URL="https://sepolia.etherscan.io/tx/"
```

That's it — the next case you analyze will mine a local block as before,
*and* broadcast an `anchorHash` transaction. `/blockchain` shows each
block's on-chain status (submitted → confirmed, usually within a block or
two) with a link to view the transaction on Etherscan, plus a **Verify**
button that re-checks a hash straight from the contract — independent of
this app's own database — so the "don't trust this server" claim is
actually checkable, not just asserted.

If you'd rather use Polygon Amoy or another EVM-compatible testnet instead
of Sepolia, the setup is identical — just point `WEB3_RPC_URL` at that
network's RPC, deploy the same contract there, and set
`WEB3_EXPLORER_BASE_URL` to that network's explorer.

## Rate limiting in production

`RATELIMIT_STORAGE_URI` defaults to `memory://`, which is fine for a
single dev process but is **per-worker** — running gunicorn with multiple
workers means each worker enforces the login/signup/analyze limits
independently, so the effective limit is multiplied by the worker count.
For a real multi-worker deployment, point it at Redis:

```bash
export RATELIMIT_STORAGE_URI=redis://<host>:6379/0
```

(the `redis` package is already in `requirements.txt`). `ProductionConfig`
will warn on startup if it's still on `memory://`, same as the SQLite
warning above.

## API key access

Every account can generate one personal API key from `/account/api-key` for
calling `/api/cases` without a browser session — handy for a SIEM/SOAR or a
scheduled script pulling case data. Send it as a header:

```bash
curl -H "X-API-Key: eptk_...yourkey..." https://your-host/api/cases
```

Only the salted hash is stored (same as a password); the raw key is shown
once, at generation time. Regenerating or revoking immediately invalidates
the previous key — one active key per account, so rotation is just
"generate a new one." The key only works against `/api/cases`, not the rest
of the app, so a leaked key can't be used to browse or change anything.

## Security headers & audit trail

Every response carries baseline hardening headers (`Content-Security-Policy`,
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy`, `Permissions-Policy`, and HSTS once `APP_ENV=production`)
— see `_set_security_headers` in `app.py`.

Separately, an append-only `audit_log` table records who did what and when:
signups, logins (including failed/locked-out attempts), logouts, case
analysis, verdict changes, CSV exports, model retraining, and API key
issuance/use/revocation. Any admin (`User.is_admin`) can review it at
`/admin/audit-log`, filterable by action type. This is a plain activity
log for accountability, not the tamper-evidence mechanism — that's the
blockchain evidence ledger above, which exists specifically to make
*case* evidence tampering detectable.

## Phone number / caller check

`/check-number` (linked from the nav as "Check a Call/Number") answers "is
this call genuine?" for a phone number that called or texted the user, using
the same three-tier reputation pattern as the email blacklist check:
1. This platform's own `BlacklistEntry` table (`indicator_type='phone'`).
2. `ml_model/scam_numbers.csv` — a bundled *starter* snapshot of
   community-reported scam numbers (robocalls, bank/IRS impersonation,
   one-ring toll fraud, etc.). There's no single free authoritative feed for
   scam numbers the way PhishTank exists for phishing URLs, so this is meant
   to be grown over time from sources like FTC DoNotCall complaint exports
   or user-submitted reports, rather than auto-refreshed like PhishTank is.
3. Optional live lookup via IPQualityScore's phone API (see above) for a
   fraud score, carrier, and line type (VoIP lines combined with other
   signals are a common spoofed-caller-ID pattern, so that's called out
   specifically).

Numbers are normalized with the `phonenumbers` package so formatting
differences ("+1 800-555-0172" vs "8005550172") still match; it degrades to
a plain digit-strip if that package isn't installed.

## Voice accessibility layer

`static/js/voice.js` wraps the browser's built-in Web Speech API (no server
round-trip, no extra API key) and is shared across pages:
- **Read result aloud** — on both `/check-number` and an email's
  `result.html`, so the verdict can be listened to rather than read. Aimed
  at users (e.g. elderly users) who find listening easier than reading a
  score breakdown.
- **Speak instead of typing** — the "Speak instead" mic button on
  `/check-number` lets the user say the suspicious number out loud instead
  of typing it.

Both affordances check for browser support first and hide themselves if the
browser doesn't implement the API (e.g. some non-Chromium browsers lack
`SpeechRecognition`) -- voice is always an addition on top of the normal
form/text flow, never a replacement for it.

## Next steps to extend

1. Add MaxMind GeoLite2 as an offline fallback GeoIP source alongside ip-api.com.
2. Upgrade `modules/mailbox_connector.py`'s Outlook/Exchange path from
   IMAP/app-password to full Microsoft Graph OAuth (`msal`), matching what
   `modules/oauth_gmail.py` already does for Gmail.
3. `ml_model/phishtank_domains.csv` is refreshed on a schedule (see
   `.github/workflows/refresh-phishtank.yml`) — extend the same pattern to
   auto-refresh `ml_model/training_dataset.csv` from larger/updated corpora.
4. Move on-chain anchoring off Sepolia and onto a production-grade chain
   (or a permissioned one like Hyperledger Fabric) if this goes to real
   production use — Sepolia is a testnet and can be reset/deprecated.