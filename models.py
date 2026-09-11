from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Case(db.Model):
    __tablename__ = 'cases'

    id = db.Column(db.Integer, primary_key=True)
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


class FeedbackLog(db.Model):
    """Tracks analyst feedback used to retrain the ML classifier
    (Self-improving model / feedback loop USP)."""
    __tablename__ = 'feedback_log'

    id = db.Column(db.Integer, primary_key=True)
    case_ref = db.Column(db.String(32))
    verdict = db.Column(db.String(24))  # 'Confirmed Phishing' or 'False Positive'
    used_in_training = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)