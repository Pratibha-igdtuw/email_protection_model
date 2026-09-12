# AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

One upload -> content AI classifier, geolocation trace, SPF/DKIM/DMARC
authentication check, WHOIS + blacklist/PhishTank reputation — merged into a
single combined risk score (0-100) with a severity verdict
(Low/Medium/High/Critical), a downloadable PDF forensic report, and a
blockchain-anchored evidence ledger for chain of custody.

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
seeded demo user.

- `/` — public landing page
- `/signup`, `/login`, `/logout` — account creation and session management
- `/app` — paste raw email source or upload a `.eml` file, run analysis
- `/connect-mailbox` — Gmail via OAuth2 (if configured, see below) or
  IMAP with an app password for Gmail/Outlook/Exchange
- `/dashboard` — analyst queue: search, filter by severity, export CSV, retrain model
- `/dashboard/map` — geolocated cases on a live map
- `/dashboard/clusters` — repeat-offender / coordinated-campaign clustering
- `/case/<case_ref>` — case detail, analyst notes, feedback verdict buttons
- `/report/<case_ref>` — download the generated PDF forensic report
- `/blockchain` — the append-only evidence hash-chain, plus each block's
  public on-chain anchoring status (see "Real blockchain anchoring setup" below)
- `/api/cases` — JSON list of your analyzed cases

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
  parser.py                 Module 1: header/body parser, Received chain, IP extraction
  classifier.py              Module 1: ML phishing classifier + NLP social-engineering cues
  geoip.py                   Module 2: IP geolocation (ip-api.com) + brand/hosting mismatch
  whois_lookup.py             Module 3: WHOIS domain age check
  auth_check.py               Module 3: SPF / DKIM / DMARC verification (headers + optional live DNS)
  blacklist.py                Module 3: local blacklist + PhishTank-verified domain check + optional AbuseIPDB
  clustering.py               Repeat-offender / coordinated-campaign clustering
  risk_score.py               Module 4: combined weighted risk score + severity banding
  report_gen.py               Module 3: PDF forensic report (ReportLab)
  chain_of_custody.py          SHA-256 evidence hashing + custody record
  blockchain.py                Local append-only hash-chain (mined per case)
  blockchain_anchor.py          Real on-chain anchoring via web3.py (optional, see below)
  oauth_gmail.py               Gmail OAuth2 connector
  mailbox_connector.py         IMAP app-password connector (Gmail/Outlook/Exchange)
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

- **GeoIP** uses ip-api.com's free tier (no key needed). If the runtime
  environment has no outbound internet access, this gracefully falls back to
  a "lookup unavailable" status rather than breaking the pipeline.
- **WHOIS** uses `python-whois`, which queries public WHOIS servers directly —
  same graceful fallback applies if network access is restricted.
- **AbuseIPDB** blacklist check is optional: set the `ABUSEIPDB_API_KEY`
  environment variable to enable it. Without a key it just reports
  `not_configured` and the local blacklist table still works standalone.
- **DMARC** policy is read from the `Authentication-Results` header first
  (works fully offline); a live DNS TXT lookup via `dnspython` is attempted
  as a secondary confirmation and silently skipped if unavailable.

## Combined risk score weighting

| Component                        | Max points |
|-----------------------------------|-----------|
| ML content phishing probability   | 30 |
| NLP/heuristic red flags            | 20 |
| SPF/DKIM/DMARC authentication      | 30 (highest weight — strongest spoofing signal) |
| Blacklist/reputation                | 20 |
| WHOIS newly-registered domain (<30d)| +10 flat |
| GeoIP brand/hosting mismatch        | +10 flat |

Total capped at 100. Bands: 0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical.

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

`migrations/versions/` currently holds a single migration that creates the
full schema from scratch (including the blockchain ledger's `chain_blocks`
table) — safe to run against a genuinely empty database. After changing any
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
