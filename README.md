# AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

One upload -> content AI classifier, geolocation trace, SPF/DKIM/DMARC
authentication check, WHOIS + blacklist reputation — merged into a single
combined risk score (0-100) with a severity verdict (Low/Medium/High/Critical)
and a downloadable PDF forensic report.

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

The baseline ML phishing classifier is already trained and included
(`ml_model/phishing_model.joblib`). To retrain (e.g. after swapping in a
larger public dataset like Enron/SpamAssassin/Nazario/PhishTank):

```bash
python ml_model/train_model.py
```

## Run

```bash
python app.py
```

Visit **http://localhost:5000**

- `/` — paste raw email source or upload a `.eml` file, run analysis
- `/dashboard` — analyst queue: search, filter by severity, export CSV
- `/case/<case_ref>` — case detail + analyst notes
- `/report/<case_ref>` — download the generated PDF forensic report
- `/api/cases` — JSON list of all analyzed cases

Two ready-to-use test emails are in `sample_emails/`:
- `phishing_sample.eml` — spoofed PayPal email with SPF/DKIM/DMARC failures,
  a lookalike domain, urgency language, and a shortened link (expect High/Critical).
- `legit_sample.eml` — normal internal email with passing SPF/DKIM/DMARC
  (expect Low score).

## Project structure

```
app.py                  Flask routes + pipeline orchestration
models.py                SQLAlchemy models (Case, BlacklistEntry)
modules/
  parser.py               Module 1: header/body parser, Received chain, IP extraction
  classifier.py            Module 1: ML phishing classifier + NLP social-engineering cues
  geoip.py                 Module 2: IP geolocation (ip-api.com) + brand/hosting mismatch
  whois_lookup.py           Module 3: WHOIS domain age check
  auth_check.py             Module 3: SPF / DKIM / DMARC verification (headers + optional live DNS)
  blacklist.py              Module 3: local blacklist + optional AbuseIPDB reputation check
  risk_score.py             Module 4: combined weighted risk score + severity banding
  report_gen.py             Module 3: PDF forensic report (ReportLab)
templates/                Bootstrap 5 UI (upload, result, dashboard, case detail)
static/css/style.css       Custom styling
ml_model/
  sample_dataset.csv        Small bundled training set (swap for a bigger public corpus)
  train_model.py             Retrains the Naive Bayes/TF-IDF classifier
  phishing_model.joblib      Pre-trained model (included, ready to use)
sample_emails/             Two .eml files for quick testing
case_reports/               Generated PDF reports + stored raw .eml files (created at runtime)
instance/                  SQLite database (created at runtime)
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

## Next steps to extend

1. Swap `ml_model/sample_dataset.csv` for a real public corpus (Enron,
   SpamAssassin, Nazario, PhishTank) and re-run `train_model.py`.
2. Add MaxMind GeoLite2 as an offline fallback GeoIP source alongside ip-api.com.
3. Add a relay-path map visualization on the result page (Leaflet.js + the
   lat/lon already returned by `geoip.py`).
4. Add role-based auth (analyst/admin) if this becomes multi-user.
