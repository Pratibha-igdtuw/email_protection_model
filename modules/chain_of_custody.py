"""
USP 4 (chain-of-custody piece): Generates a SHA-256 hash of the raw email
bytes at ingestion time and again at report-generation time, so any later
tampering with the stored evidence file is detectable — the core idea of
digital chain-of-custody used in forensic reporting aligned with
IT Act 2000 / CERT-In incident reporting practice.
"""
import hashlib
from datetime import datetime, timezone


def compute_sha256(raw_bytes):
    return hashlib.sha256(raw_bytes).hexdigest()


def verify_integrity(raw_email_path, expected_hash):
    """Re-hash the stored .eml file and compare to the hash recorded at
    ingestion time. Returns True if the evidence is unmodified."""
    try:
        with open(raw_email_path, 'rb') as f:
            current_hash = compute_sha256(f.read())
        return current_hash == expected_hash, current_hash
    except FileNotFoundError:
        return False, None


def build_custody_record(case_ref, raw_email_path, evidence_hash, analyst='System (automated ingestion)'):
    """Chain-of-custody metadata block, formatted for inclusion in the
    forensic PDF report — mirrors the fields typically expected in a
    CERT-In / IT Act 2000 aligned incident evidence record."""
    verified, current_hash = verify_integrity(raw_email_path, evidence_hash)
    return {
        'case_ref': case_ref,
        'evidence_file': raw_email_path,
        'sha256_at_ingestion': evidence_hash,
        'sha256_at_report_time': current_hash,
        'integrity_verified': verified,
        'custodian': analyst,
        'hash_algorithm': 'SHA-256',
        'record_generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'compliance_note': ("Report structured to support incident reporting under the "
                             "Information Technology Act, 2000 and CERT-In incident reporting "
                             "guidelines. Includes: unique incident reference, timestamped evidence "
                             "hash, unmodified original header/body preservation, and an auditable "
                             "analyst trail."),
    }
