from flask import render_template, request, jsonify, flash, redirect, url_for
from app import app
from extensions import db
from models import URLAnalysis
from phishing_detector import PhishingDetector
import json
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Initialize the phishing detector
detector = PhishingDetector()

@app.route('/')
def index():
    """Main page with URL input form"""
    # Get recent analyses for display (last 10)
    recent_analyses = URLAnalysis.query.order_by(URLAnalysis.created_at.desc()).limit(10).all()
    return render_template('index.html', recent_analyses=recent_analyses)

@app.route('/analyze', methods=['POST'])
def analyze_url():
    """Analyze URL for phishing detection"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        # Basic URL validation
        if not _is_valid_url(url):
            return jsonify({'error': 'Please enter a valid URL'}), 400
        
        # Get client IP for rate limiting
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        logger.info(f"Analyzing URL: {url} from IP: {client_ip}")
        
        # Perform phishing analysis
        result = detector.analyze_url(url)
        
        # Save analysis to database
        analysis = URLAnalysis()
        analysis.url = result['url']
        analysis.is_phishing = result['is_phishing']
        analysis.confidence_score = result['confidence_score']
        analysis.analysis_details = json.dumps(result['analysis_details'])  # JSON stringify for database
        analysis.ip_address = client_ip
        
        db.session.add(analysis)
        db.session.commit()
        
        # Prepare response
        response_data = {
            'id': analysis.id,
            'url': result['url'],
            'is_phishing': result['is_phishing'],
            'confidence_score': round(result['confidence_score'], 3),
            'risk_level': result['risk_level'],
            'recommendations': result['recommendations'],
            'analysis_details': result['analysis_details'],  # Use dict directly
            'timestamp': analysis.created_at.isoformat()
        }
        
        logger.info(f"Analysis complete for {url}: {'PHISHING' if result['is_phishing'] else 'SAFE'}")
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error during URL analysis: {e}")
        return jsonify({'error': 'An error occurred during analysis. Please try again.'}), 500

@app.route('/history')
def history():
    """View analysis history"""
    page = request.args.get('page', 1, type=int)
    analyses = URLAnalysis.query.order_by(URLAnalysis.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    # Add a custom filter for JSON parsing in templates
    app.jinja_env.filters['from_json'] = json.loads
    
    return render_template('history.html', analyses=analyses)

@app.route('/api/stats')
def get_stats():
    """Get analysis statistics"""
    try:
        total_analyses = URLAnalysis.query.count()
        phishing_count = URLAnalysis.query.filter_by(is_phishing=True).count()
        safe_count = total_analyses - phishing_count
        
        stats = {
            'total_analyses': total_analyses,
            'phishing_detected': phishing_count,
            'safe_urls': safe_count,
            'phishing_percentage': round((phishing_count / total_analyses * 100) if total_analyses > 0 else 0, 1)
        }
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': 'Unable to retrieve statistics'}), 500

@app.route('/about')
def about():
    """About page with information about phishing detection"""
    return render_template('about.html')

def _is_valid_url(url):
    """Basic URL validation - accepts URLs with or without protocol, including paths"""
    try:
        url = url.strip()
        
        # Basic validation: must not be empty and not contain spaces
        if not url or ' ' in url:
            return False
        
        # For validation, temporarily add protocol if missing
        test_url = url
        if not url.startswith(('http://', 'https://')):
            test_url = 'https://' + url
        
        result = urlparse(test_url)
        
        # Valid if has netloc (domain)
        if not result.netloc:
            return False
        
        # Accept localhost or any domain with at least one dot
        netloc = result.netloc.lower()
        if netloc == 'localhost' or netloc.startswith('localhost:'):
            return True
        
        # Must contain at least one dot for regular domains
        return '.' in netloc
    except:
        return False

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
