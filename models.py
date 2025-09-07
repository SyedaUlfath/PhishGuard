from extensions import db
from datetime import datetime

class URLAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False)
    is_phishing = db.Column(db.Boolean, nullable=False)
    confidence_score = db.Column(db.Float, nullable=False)
    analysis_details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))  # Store client IP for rate limiting

    def __repr__(self):
        return f'<URLAnalysis {self.url}>'

    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'is_phishing': self.is_phishing,
            'confidence_score': self.confidence_score,
            'analysis_details': self.analysis_details,
            'created_at': self.created_at.isoformat(),
            'result': 'PHISHING' if self.is_phishing else 'SAFE'
        }
