from datetime import datetime
import os
import secrets
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken

db = SQLAlchemy()


def _fernet():
    key = os.environ.get('TOKEN_ENCRYPTION_KEY')
    if not key:
        raise RuntimeError(
            'TOKEN_ENCRYPTION_KEY env var is not set -- mailbox OAuth tokens '
            'cannot be encrypted/decrypted without it. Generate one once with:\n'
            '  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"\n'
            'then set it as TOKEN_ENCRYPTION_KEY before starting the app (keep '
            'it out of source control -- .env / your host\'s secret manager).'
        )
    return Fernet(key.encode())


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    organization = db.Column(db.String(255))
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Programmatic access (e.g. a SOAR/SIEM pulling /api/cases on a schedule)
    # without sharing a session cookie. Stored as a salted hash, same as a
    # password -- the raw key is shown to the user exactly once, at
    # generation time, and is never recoverable from the DB afterwards.
    api_key_hash = db.Column(db.String(255), nullable=True)
    api_key_prefix = db.Column(db.String(8), nullable=True)  # shown in UI so a user can tell keys apart
    api_key_created_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)

    def generate_api_key(self):
        """Creates a new API key, stores only its hash, and returns the raw
        key once. Any previously issued key stops working immediately
        (single active key per user keeps revocation simple: regenerating
        IS revoking)."""
        raw_key = f"eptk_{secrets.token_urlsafe(32)}"  # eptk = Email Protection Threat Key
        self.api_key_hash = generate_password_hash(raw_key)
        self.api_key_prefix = raw_key[:12]
        self.api_key_created_at = datetime.utcnow()
        return raw_key

    def check_api_key(self, raw_key):
        if not self.api_key_hash or not raw_key:
            return False
        return check_password_hash(self.api_key_hash, raw_key)

    def revoke_api_key(self):
        self.api_key_hash = None
        self.api_key_prefix = None
        self.api_key_created_at = None

    LOCKOUT_THRESHOLD = 5
    LOCKOUT_DURATION_MINUTES = 15

    def is_locked(self):
        return self.locked_until is not None and self.locked_until > datetime.utcnow()

    def register_failed_login(self):
        """Per-account lockout, on top of the existing per-IP rate limit on
        /login -- an IP-only limit doesn't stop credential stuffing spread
        across many accounts from one IP, or distributed across many IPs
        against one account."""
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        if self.failed_login_attempts >= self.LOCKOUT_THRESHOLD:
            from datetime import timedelta
            self.locked_until = datetime.utcnow() + timedelta(minutes=self.LOCKOUT_DURATION_MINUTES)
            self.failed_login_attempts = 0

    def register_successful_login(self):
        self.failed_login_attempts = 0
        self.locked_until = None

    @property
    def initials(self):
        parts = [p for p in self.full_name.split() if p]
        if not parts:
            return self.email[:2].upper()
        if len(parts) == 1:
            return parts[0][:2].upper()
        return (parts[0][0] + parts[-1][0]).upper()


class Case(db.Model):
    __tablename__ = 'cases'

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    case_ref = db.Column(db.String(32), unique=True, nullable=False)
    subject = db.Column(db.String(512))
    sender_from = db.Column(db.String(512))
    sender_domain = db.Column(db.String(255))
    originating_ip = db.Column(db.String(64))
    combined_score = db.Column(db.Float, default=0.0)
    severity = db.Column(db.String(16), default='Low')
    ml_probability = db.Column(db.Float, default=0.0)
    spf_result = db.Column(db.String(16))
    dkim_result = db.Column(db.String(32))
    dmarc_result = db.Column(db.String(16))
    country = db.Column(db.String(128))

    # Geolocation clustering / map fields
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    asn = db.Column(db.String(64))
    isp = db.Column(db.String(255))

    # Forensic chain-of-custody
    evidence_sha256 = db.Column(db.String(64))
    hash_generated_at = db.Column(db.DateTime)

    # Self-improving feedback loop
    analyst_verdict = db.Column(db.String(24), default='Unreviewed')  # Unreviewed / Confirmed Phishing / False Positive
    body_text = db.Column(db.Text)  # stored for retraining on feedback

    analyst_notes = db.Column(db.Text)
    report_path = db.Column(db.String(512))
    raw_email_path = db.Column(db.String(512))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship('User', backref=db.backref('cases', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'case_ref': self.case_ref,
            'subject': self.subject,
            'sender_from': self.sender_from,
            'sender_domain': self.sender_domain,
            'originating_ip': self.originating_ip,
            'combined_score': self.combined_score,
            'severity': self.severity,
            'ml_probability': self.ml_probability,
            'spf_result': self.spf_result,
            'dkim_result': self.dkim_result,
            'dmarc_result': self.dmarc_result,
            'country': self.country,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'asn': self.asn,
            'isp': self.isp,
            'evidence_sha256': self.evidence_sha256,
            'analyst_verdict': self.analyst_verdict,
            'analyst_notes': self.analyst_notes,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M'),
        }


class BlacklistEntry(db.Model):
    __tablename__ = 'blacklist_entries'

    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(255), nullable=False)
    indicator_type = db.Column(db.String(16), nullable=False)  # 'ip' or 'domain'
    reason = db.Column(db.String(512))
    added_on = db.Column(db.DateTime, default=datetime.utcnow)


class MailboxOAuthToken(db.Model):
    """OAuth2 refresh/access tokens for the Gmail API mailbox connector
    (USP 6 upgrade: OAuth instead of an IMAP app password). One row per
    user+provider. Tokens are the user's own credential to their mailbox,
    scoped to read-only mail access -- never shared across users.

    access_token / refresh_token are encrypted at rest (Fernet, see
    TOKEN_ENCRYPTION_KEY) -- a raw DB dump alone is not enough to use them.
    The DB column names are unchanged (access_token / refresh_token), so
    this needs no migration; only the stored content is now ciphertext."""
    __tablename__ = 'mailbox_oauth_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    provider = db.Column(db.String(32), nullable=False, default='gmail')
    _access_token = db.Column('access_token', db.Text, nullable=False)
    _refresh_token = db.Column('refresh_token', db.Text)
    token_expiry = db.Column(db.DateTime)
    scope = db.Column(db.Text)
    mailbox_email = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('mailbox_tokens', lazy='dynamic'))

    __table_args__ = (db.UniqueConstraint('user_id', 'provider', name='uq_user_provider'),)

    @property
    def access_token(self):
        return self._decrypt(self._access_token)

    @access_token.setter
    def access_token(self, value):
        self._access_token = self._encrypt(value)

    @property
    def refresh_token(self):
        return self._decrypt(self._refresh_token)

    @refresh_token.setter
    def refresh_token(self, value):
        self._refresh_token = self._encrypt(value)

    @staticmethod
    def _encrypt(value):
        if value is None:
            return None
        return _fernet().encrypt(value.encode('utf-8')).decode('utf-8')

    @staticmethod
    def _decrypt(value):
        if value is None:
            return None
        try:
            return _fernet().decrypt(value.encode('utf-8')).decode('utf-8')
        except InvalidToken:
            # Wrong/rotated TOKEN_ENCRYPTION_KEY, or corrupt data -- treat as
            # unusable rather than silently returning ciphertext to callers.
            return None


class FeedbackLog(db.Model):
    """Tracks analyst feedback used to retrain the ML classifier
    (Self-improving model / feedback loop USP)."""
    __tablename__ = 'feedback_log'

    id = db.Column(db.Integer, primary_key=True)
    case_ref = db.Column(db.String(32))
    verdict = db.Column(db.String(24))  # 'Confirmed Phishing' or 'False Positive'
    used_in_training = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    """Append-style activity trail for the platform itself -- who signed in,
    who ran an analysis, who changed a verdict, who exported data, who
    triggered a retrain. Separate from the evidence hash-chain (ChainBlock,
    below), which attests to *case* integrity; this attests to *user
    activity*, which a forensic/security tool is expected to be able to
    show an auditor on request (e.g. "who accessed this case and when").

    Deliberately never updated or deleted through the app -- rows are only
    ever inserted, so the log itself can't be quietly edited after the fact
    by anything short of direct DB access."""
    __tablename__ = 'audit_log'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    target = db.Column(db.String(255), nullable=True)  # e.g. a case_ref, or another user's email
    detail = db.Column(db.String(512), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    user = db.relationship('User', backref=db.backref('audit_entries', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'user_email': self.user.email if self.user else None,
            'action': self.action,
            'target': self.target,
            'detail': self.detail,
            'ip_address': self.ip_address,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.created_at else None,
        }


class ChainBlock(db.Model):
    """Append-only hash chain -- the blockchain piece of the forensic
    evidence trail (see modules/blockchain.py for the chaining logic).

    One block is mined per case. Each block commits to the previous
    block's hash, so editing any past block (or the case evidence it
    attests to) changes that block's hash and breaks every link after
    it -- detectable by walking the chain with blockchain.verify_chain(),
    without needing to trust any single row in isolation."""
    __tablename__ = 'chain_blocks'

    id = db.Column(db.Integer, primary_key=True)
    block_index = db.Column(db.Integer, unique=True, nullable=False)
    case_ref = db.Column(db.String(32), nullable=False, index=True)
    evidence_sha256 = db.Column(db.String(64), nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)
    block_hash = db.Column(db.String(64), nullable=False)
    nonce = db.Column(db.Integer, default=0, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Real-blockchain anchoring (modules/blockchain_anchor.py) -- publishes
    # block_hash to a public Ethereum-compatible testnet via the
    # EvidenceAnchor smart contract, independent of this app's own database.
    # onchain_status: not_configured | submitted | confirmed | failed
    onchain_status = db.Column(db.String(24), default='not_configured', nullable=False)
    onchain_tx_hash = db.Column(db.String(80))
    onchain_network = db.Column(db.String(32))
    onchain_confirmed_at = db.Column(db.DateTime)
    onchain_error = db.Column(db.Text)

    def to_dict(self):
        return {
            'block_index': self.block_index,
            'case_ref': self.case_ref,
            'evidence_sha256': self.evidence_sha256,
            'previous_hash': self.previous_hash,
            'block_hash': self.block_hash,
            'nonce': self.nonce,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') if self.timestamp else None,
            'onchain_status': self.onchain_status,
            'onchain_tx_hash': self.onchain_tx_hash,
            'onchain_network': self.onchain_network,
        }