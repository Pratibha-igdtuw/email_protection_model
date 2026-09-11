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
