import os
import logging
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from extensions import db  # single shared db instance

logging.basicConfig(level=logging.DEBUG)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///phishing_detector.db"
)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Bind db to app before importing models or routes
db.init_app(app)

# Create tables after binding db
with app.app_context():
    # Import models after db is initialized
    from models import URLAnalysis
    db.create_all()

# Import routes after db + models are ready
import routes

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
