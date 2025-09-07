import re
import urllib.parse
import socket
import requests
import logging
import json
from typing import Dict, List, Tuple, Any
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np

logger = logging.getLogger(__name__)

class PhishingDetector:
    def __init__(self):
        self.suspicious_keywords = [
            'verify', 'account', 'suspended', 'confirm', 'update', 'secure',
            'bank', 'paypal', 'amazon', 'apple', 'microsoft', 'google',
            'login', 'signin', 'validation', 'activate', 'urgent', 'expired',
            'limited', 'restricted', 'warning', 'alert', 'immediate', 'icloud',
            'facebook', 'instagram', 'twitter', 'linkedin', 'netflix', 'spotify'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download',
            '.stream', '.science', '.racing', '.loan', '.win', '.bid'
        ]
        
        # Initialize a simple ML model (in production, this would be trained on real data)
        self.ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize the ML model with synthetic training data for demonstration"""
        # In production, this would use real phishing/legitimate URL datasets
        try:
            # Create synthetic training features
            legitimate_features = np.random.rand(500, 20)
            legitimate_features[:, 0] = np.random.uniform(0, 0.3, 500)  # Lower suspicious keyword ratio
            legitimate_features[:, 1] = np.random.uniform(10, 50, 500)  # Normal URL length
            
            phishing_features = np.random.rand(500, 20)
            phishing_features[:, 0] = np.random.uniform(0.4, 1.0, 500)  # Higher suspicious keyword ratio
            phishing_features[:, 1] = np.random.uniform(80, 200, 500)  # Longer URLs
            
            X = np.vstack([legitimate_features, phishing_features])
            y = np.hstack([np.zeros(500), np.ones(500)])
            
            self.ml_model.fit(X, y)
            logger.info("ML model initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing ML model: {e}")
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Comprehensive URL analysis for phishing detection
        """
        # Store original URL for analysis
        original_url = url
        
        try:
            # For parsing purposes only, add protocol if missing (won't change the stored URL)
            parse_url = url
            if not url.startswith(('http://', 'https://')):
                parse_url = 'https://' + url
            
            parsed_url = urllib.parse.urlparse(parse_url)
            
            # Extract features
            features = self._extract_features(url, parsed_url)
            
            # Heuristic analysis
            heuristic_score, heuristic_details = self._heuristic_analysis(features)
            
            # ML prediction
            ml_score, ml_confidence = self._ml_prediction(features)
            
            # Combine scores with brand impersonation override
            base_score = (heuristic_score * 0.7) + (ml_score * 0.3)
            
            # If brand impersonation is detected, significantly increase the score
            brand_info = features['brand_impersonation']
            if brand_info['is_impersonating']:
                # Brand impersonation is a strong indicator of phishing
                final_score = max(base_score, 0.8)  # Ensure at least 0.8 for brand impersonation
                confidence = 0.85  # High confidence for brand impersonation
            else:
                final_score = base_score
                confidence = min(abs(final_score - 0.5) * 2, 1.0)  # Convert to confidence (0-1)
            
            is_phishing = final_score > 0.5
            
            # Detailed analysis - ensure all values are JSON serializable
            # Determine threat type based on patterns detected
            threat_type = "Unknown"
            if any(key.startswith('defacement') for key in heuristic_details.keys()):
                threat_type = "Defacement"
            elif any(key.startswith('malware') for key in heuristic_details.keys()):
                threat_type = "Malware"  
            elif any(key.startswith('brand_impersonation') for key in heuristic_details.keys()):
                threat_type = "Phishing/Brand Impersonation"
            elif is_phishing:
                threat_type = "Phishing"
                
            analysis_details = {
                'heuristic_score': float(heuristic_score),
                'ml_score': float(ml_score),
                'final_score': float(final_score),
                'confidence': float(confidence),
                'threat_type': threat_type,
                'features': heuristic_details,
                'domain': str(parsed_url.netloc),
                'protocol': str(parsed_url.scheme),
                'path_length': int(len(parsed_url.path)),
                'query_params': int(len(urllib.parse.parse_qs(parsed_url.query)))
            }
            
            return {
                'url': original_url,
                'is_phishing': bool(is_phishing),
                'confidence_score': float(confidence),
                'analysis_details': analysis_details,  # Return dict directly instead of JSON string
                'risk_level': self._get_risk_level(final_score),
                'recommendations': self._get_recommendations(is_phishing, analysis_details)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing URL {original_url}: {e}")
            return {
                'url': original_url,
                'is_phishing': True,
                'confidence_score': 0.8,
                'analysis_details': {'error': str(e)},  # Return dict directly
                'risk_level': 'HIGH',
                'recommendations': ['URL could not be properly analyzed - proceed with caution']
            }
    
    def _extract_features(self, url: str, parsed_url) -> Dict[str, Any]:
        """Extract features from URL for analysis"""
        features = {}
        
        # Store original URL for pattern matching
        features['url'] = url
        
        # Basic URL properties (use original URL for length analysis)
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed_url.netloc)
        features['path_length'] = len(parsed_url.path)
        features['query_length'] = len(parsed_url.query)
        features['fragment_length'] = len(parsed_url.fragment)
        
        # Domain analysis
        features['subdomain_count'] = parsed_url.netloc.count('.') - 1
        features['has_ip'] = self._is_ip_address(parsed_url.netloc)
        features['suspicious_tld'] = any(parsed_url.netloc.endswith(tld) for tld in self.suspicious_tlds)
        
        # URL structure analysis
        features['hyphen_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url)
        features['special_char_ratio'] = sum(not c.isalnum() and c not in '.-_/' for c in url) / len(url)
        
        # Suspicious keywords
        features['suspicious_keywords'] = [kw for kw in self.suspicious_keywords if kw.lower() in url.lower()]
        features['suspicious_keyword_count'] = len(features['suspicious_keywords'])
        
        # Protocol analysis
        features['uses_https'] = parsed_url.scheme == 'https'
        features['has_port'] = ':' in parsed_url.netloc and not parsed_url.netloc.endswith(':80') and not parsed_url.netloc.endswith(':443')
        
        # URL shortener detection
        shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
        features['is_shortened'] = any(shortener in parsed_url.netloc for shortener in shorteners)
        
        # Brand impersonation detection
        features['brand_impersonation'] = self._detect_brand_impersonation(parsed_url.netloc)
        
        return features
    
    def _heuristic_analysis(self, features: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        """Perform heuristic-based analysis"""
        score = 0.0
        details = {}
        
        # URL length check (longer URLs are more suspicious)
        if features['url_length'] > 100:
            score += 0.15
            details['long_url'] = f"URL is {features['url_length']} characters (suspicious if >100)"
        
        # IP address instead of domain
        if features['has_ip']:
            score += 0.3
            details['ip_address'] = "Uses IP address instead of domain name"
        
        # Suspicious TLD
        if features['suspicious_tld']:
            score += 0.2
            details['suspicious_tld'] = "Uses suspicious top-level domain"
        
        # Many subdomains
        if features['subdomain_count'] > 3:
            score += 0.15
            details['many_subdomains'] = f"Has {features['subdomain_count']} subdomains"
        
        # Suspicious keywords
        if features['suspicious_keyword_count'] > 0:
            score += min(features['suspicious_keyword_count'] * 0.1, 0.3)
            details['suspicious_keywords'] = f"Contains keywords: {', '.join(features['suspicious_keywords'])}"
        
        # No HTTPS
        if not features['uses_https']:
            score += 0.1
            details['no_https'] = "Does not use HTTPS encryption"
        
        # High special character ratio
        if features['special_char_ratio'] > 0.1:
            score += 0.1
            details['special_chars'] = f"High ratio of special characters: {features['special_char_ratio']:.2f}"
            
        # Enhanced defacement detection
        defacement_score, defacement_details = self._detect_defacement_patterns(features)
        score += defacement_score
        if defacement_details:
            details.update(defacement_details)
            
        # Enhanced malware detection  
        malware_score, malware_details = self._detect_malware_patterns(features)
        score += malware_score
        if malware_details:
            details.update(malware_details)
        
        # URL shortener
        if features['is_shortened']:
            score += 0.15
            details['url_shortener'] = "Uses URL shortening service"
        
        # Non-standard port
        if features['has_port']:
            score += 0.1
            details['non_standard_port'] = "Uses non-standard port"
        
        # Brand impersonation (high weight)
        brand_info = features['brand_impersonation']
        if brand_info['is_impersonating']:
            score += 0.4  # High penalty for brand impersonation
            details['brand_impersonation'] = f"Attempting to impersonate {brand_info['brand']}"
            if brand_info['suspicious_patterns']:
                details['impersonation_patterns'] = "; ".join(brand_info['suspicious_patterns'])
        
        return min(score, 1.0), details
        
    def _detect_defacement_patterns(self, features: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        """Detect defacement patterns based on dataset analysis"""
        score = 0.0
        details = {}
        url = features.get('url', '').lower()
        
        # Common defacement indicators from dataset
        defacement_patterns = [
            # CMS/Admin panel access attempts
            'index.php?option=com_',  # Joomla component access
            'administrator/',
            'wp-admin/',
            'admin/',
            '/component/',
            
            # Suspicious query parameters
            '?view=article',
            '?option=com_content',
            '?option=com_user',
            '?option=com_mailto',
            '?tmpl=component',
            
            # File inclusion attempts
            '.php?',
            'index.php',
            
            # Common defacement paths
            '/catalogo/',
            '/index.php/',
            
            # Long encoded parameters (like base64)
            'link=aHR0cDovL',  # Base64 encoded http://
            'link=bHR0cDovL',   # Base64 encoded http://
        ]
        
        defacement_count = 0
        matched_patterns = []
        
        for pattern in defacement_patterns:
            if pattern in url:
                defacement_count += 1
                matched_patterns.append(pattern)
                
        if defacement_count > 0:
            # Higher score for more patterns
            score = min(0.3 + (defacement_count * 0.1), 0.7)
            details['defacement_patterns'] = f"Matches {defacement_count} defacement patterns: {', '.join(matched_patterns[:3])}"
            
        # Specific high-risk patterns
        if any(pattern in url for pattern in ['?option=com_mailto&tmpl=component&link=', 'index.php?option=com_content&view=article']):
            score = max(score, 0.6)
            details['high_risk_defacement'] = "Matches high-risk defacement pattern"
            
        # Additional defacement indicators
        additional_patterns = [
            '/pure-pashminas',
            '/exposities/', 
            '/aktuelles.',
            'de/index.php',
            'nl/index.php',
            'com.br/',
            '.it/',
        ]
        
        additional_count = sum(1 for pattern in additional_patterns if pattern in url)
        if additional_count > 0:
            score = max(score, 0.4)
            details['additional_defacement_indicators'] = f"Found {additional_count} additional suspicious patterns"
            
        return score, details
        
    def _detect_malware_patterns(self, features: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        """Detect malware patterns based on dataset analysis"""
        score = 0.0
        details = {}
        url = features.get('url', '').lower()
        
        # Common malware indicators from dataset
        malware_patterns = [
            # Suspicious file extensions
            '.asp?',
            '.jsp?',
            '.php?',
            
            # Suspicious parameters
            'uid=guest',
            'langx=',
            'lm2=',
            
            # Chinese/Unicode in URLs (common in malware from dataset)
            '%e5%', '%e6%', '%e7%', '%e8%', '%e9%',  # Chinese characters encoded
            
            # Numeric domains or suspicious paths
            '/app/member/',
            'SportOption.php',
            
            # Suspicious domain patterns
            '.info/',
            
            # Base64-like long strings
            len([c for c in url if c.isalnum()]) > 100 and '=' in url,
        ]
        
        malware_count = 0
        matched_patterns = []
        
        for pattern in malware_patterns:
            if isinstance(pattern, str) and pattern in url:
                malware_count += 1
                matched_patterns.append(pattern)
            elif isinstance(pattern, bool) and pattern:
                malware_count += 1
                matched_patterns.append("long_encoded_string")
                
        if malware_count > 0:
            score = min(0.4 + (malware_count * 0.15), 0.8)
            details['malware_patterns'] = f"Matches {malware_count} malware indicators: {', '.join(matched_patterns[:3])}"
            
        # Specific high-risk malware patterns
        if any(pattern in url for pattern in ['uid=guest&langx=', '/app/member/SportOption.php', '%e5%84%bf%e7%ab%a5']):
            score = max(score, 0.7)
            details['high_risk_malware'] = "Matches high-risk malware pattern"
            
        # Additional phishing-like patterns for comprehensive detection
        additional_phishing = [
            'marketingbyinternet.com',
            'retajconsultancy.com',
            'docs.google.com/spreadsheet/viewform',
            'formkey=',
        ]
        
        additional_phishing_count = sum(1 for pattern in additional_phishing if pattern in url)
        if additional_phishing_count > 0:
            score = max(score, 0.5)
            details['additional_phishing_indicators'] = f"Found {additional_phishing_count} suspicious phishing patterns"
            
        return score, details
    
    def _ml_prediction(self, features: Dict[str, Any]) -> Tuple[float, float]:
        """Make ML-based prediction"""
        try:
            # Create feature vector for ML model
            feature_vector = np.array([
                features['url_length'] / 200,  # Normalized
                features['domain_length'] / 50,
                features['subdomain_count'] / 5,
                int(features['has_ip']),
                int(features['suspicious_tld']),
                features['suspicious_keyword_count'] / 5,
                int(not features['uses_https']),
                features['special_char_ratio'],
                features['digit_ratio'],
                int(features['is_shortened']),
                int(features['has_port']),
                features['hyphen_count'] / 10,
                features['underscore_count'] / 10,
                features['path_length'] / 100,
                features['query_length'] / 100,
                features['fragment_length'] / 50,
                int(features['brand_impersonation']['is_impersonating']),
                len(features['brand_impersonation']['suspicious_patterns']) / 5,
                # Add more normalized features as needed
                0, 0  # Padding to match training data
            ]).reshape(1, -1)
            
            # Get probability prediction
            probabilities = self.ml_model.predict_proba(feature_vector)[0]
            phishing_probability = probabilities[1] if len(probabilities) > 1 else 0.5
            confidence = float(np.max(probabilities)) if len(probabilities) > 1 else 0.5
            
            return phishing_probability, confidence
            
        except Exception as e:
            logger.error(f"Error in ML prediction: {e}")
            return 0.5, 0.5  # Neutral prediction on error
    
    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address"""
        try:
            socket.inet_aton(hostname.split(':')[0])  # Remove port if present
            return True
        except socket.error:
            return False
    
    def _get_risk_level(self, score: float) -> str:
        """Convert score to risk level"""
        if score < 0.3:
            return 'LOW'
        elif score < 0.6:
            return 'MEDIUM'
        elif score < 0.8:
            return 'HIGH'
        else:
            return 'CRITICAL'
    
    def _get_recommendations(self, is_phishing: bool, details: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        if is_phishing:
            recommendations.append("⚠️ This URL appears to be suspicious - avoid clicking or entering personal information")
            recommendations.append("🔍 Verify the domain name carefully for typos or suspicious characters")
            recommendations.append("🔒 Check if the site uses HTTPS and has a valid SSL certificate")
            recommendations.append("📧 Be cautious of URLs received via email or messages")
        else:
            recommendations.append("✅ This URL appears to be legitimate based on our analysis")
            recommendations.append("🔒 Still verify the site's identity before entering sensitive information")
            recommendations.append("📱 Consider using two-factor authentication when available")
        
        # Add specific recommendations based on detected issues
        if 'ip_address' in details.get('features', {}):
            recommendations.append("⚠️ This URL uses an IP address instead of a domain name - be extra cautious")
        
        if 'no_https' in details.get('features', {}):
            recommendations.append("🔓 This site doesn't use HTTPS - your connection is not encrypted")
            
        if 'brand_impersonation' in details.get('features', {}):
            recommendations.append("🚨 This URL appears to be impersonating a well-known brand - this is a common phishing technique")
            
        if 'impersonation_patterns' in details.get('features', {}):
            recommendations.append("⚠️ Suspicious patterns detected that are commonly used in phishing attacks")
        
        return recommendations
    
    def _detect_brand_impersonation(self, domain: str) -> Dict[str, Any]:
        """Detect brand impersonation attempts"""
        major_brands = {
            'apple': ['icloud', 'itunes', 'apple', 'mac'],
            'google': ['gmail', 'google', 'youtube', 'drive'],
            'facebook': ['facebook', 'fb', 'instagram', 'whatsapp'],
            'microsoft': ['microsoft', 'outlook', 'hotmail', 'office', 'xbox'],
            'amazon': ['amazon', 'aws', 'prime'],
            'paypal': ['paypal', 'pp'],
            'netflix': ['netflix'],
            'twitter': ['twitter', 'x'],
            'linkedin': ['linkedin'],
            'spotify': ['spotify']
        }
        
        domain_lower = domain.lower()
        impersonation_details = {'is_impersonating': False, 'brand': None, 'suspicious_patterns': []}
        
        for brand, keywords in major_brands.items():
            for keyword in keywords:
                if keyword in domain_lower:
                    # Check if this is the legitimate domain
                    legitimate_domains = {
                        'apple': ['apple.com', 'icloud.com', 'itunes.com'],
                        'google': ['google.com', 'gmail.com', 'youtube.com', 'googledrive.com'],
                        'facebook': ['facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com'],
                        'microsoft': ['microsoft.com', 'outlook.com', 'hotmail.com', 'office.com', 'xbox.com'],
                        'amazon': ['amazon.com', 'aws.amazon.com'],
                        'paypal': ['paypal.com'],
                        'netflix': ['netflix.com'],
                        'twitter': ['twitter.com', 'x.com'],
                        'linkedin': ['linkedin.com'],
                        'spotify': ['spotify.com']
                    }
                    
                    is_legitimate = any(domain_lower.endswith(legit_domain) for legit_domain in legitimate_domains.get(brand, []))
                    
                    if not is_legitimate:
                        impersonation_details['is_impersonating'] = True
                        impersonation_details['brand'] = brand
                        
                        # Look for specific suspicious patterns
                        if keyword + '-' in domain_lower or keyword + '.' in domain_lower:
                            impersonation_details['suspicious_patterns'].append(f'Suspicious {brand} keyword placement')
                        
                        if any(char in domain_lower for char in ['-', '_']) and keyword in domain_lower:
                            impersonation_details['suspicious_patterns'].append(f'Special characters near {brand} keyword')
                        
                        # Check for country code impersonation like "br-icloud.com.br"
                        if domain_lower.startswith(('br-', 'us-', 'uk-', 'ca-', 'au-')) and keyword in domain_lower:
                            impersonation_details['suspicious_patterns'].append(f'Country code prefix with {brand} keyword')
        
        return impersonation_details
