// Phishing URL Detector - Frontend JavaScript

class PhishingDetector {
    constructor() {
        this.form = document.getElementById('urlAnalysisForm');
        this.urlInput = document.getElementById('urlInput');
        this.analyzeBtn = document.getElementById('analyzeBtn');
        this.loadingSpinner = document.getElementById('loadingSpinner');
        this.searchIcon = document.getElementById('searchIcon');
        this.errorAlert = document.getElementById('errorAlert');
        this.errorMessage = document.getElementById('errorMessage');
        this.resultsContainer = document.getElementById('resultsContainer');
        
        this.init();
        this.loadStats();
    }
    
    init() {
        // Bind form submission
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        
        // Auto-hide error alert when user starts typing
        this.urlInput.addEventListener('input', () => this.hideError());
        
        // Load stats periodically
        setInterval(() => this.loadStats(), 30000); // Every 30 seconds
    }
    
    async handleSubmit(e) {
        e.preventDefault();
        
        const url = this.urlInput.value.trim();
        if (!url) {
            this.showError('Please enter a URL to analyze');
            return;
        }
        
        // Basic client-side URL validation
        if (!this.isValidURL(url)) {
            this.showError('Please enter a valid URL (e.g., google.com, example.com/path, or https://site.com)');
            return;
        }
        
        this.setLoading(true);
        this.hideError();
        
        try {
            const result = await this.analyzeURL(url);
            this.displayResults(result);
            this.loadStats(); // Refresh stats
        } catch (error) {
            console.error('Analysis error:', error);
            this.showError(error.message || 'An error occurred during analysis. Please try again.');
        } finally {
            this.setLoading(false);
        }
    }
    
    async analyzeURL(url) {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Analysis failed');
        }
        
        return data;
    }
    
    displayResults(result) {
        // Show results container with modern animation
        this.resultsContainer.classList.remove('d-none');
        this.resultsContainer.classList.add('fade-in', 'slide-in');
        
        // Update result header and title
        const resultHeader = document.getElementById('resultHeader');
        const resultTitle = document.getElementById('resultTitle');
        const statusBadge = document.getElementById('statusBadge');
        const resultIcon = document.getElementById('resultIcon');
        
        if (result.is_phishing) {
            resultHeader.className = 'card-header gradient-bg-danger text-white';
            resultTitle.innerHTML = '<i class="fas fa-shield-exclamation me-2"></i>⚠️ Phishing Threat Detected';
            statusBadge.className = 'badge gradient-bg-danger';
            statusBadge.textContent = '🚨 THREAT';
            resultIcon.className = 'result-icon phishing pulse-animation';
            resultIcon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
        } else {
            resultHeader.className = 'card-header gradient-bg-success text-white';
            resultTitle.innerHTML = '<i class="fas fa-shield-check me-2"></i>✅ URL is Safe';
            statusBadge.className = 'badge gradient-bg-success';
            statusBadge.textContent = '✅ SAFE';
            resultIcon.className = 'result-icon safe';
            resultIcon.innerHTML = '<i class="fas fa-shield-check"></i>';
        }
        
        // Update confidence bar
        this.updateConfidenceBar(result.confidence_score);
        
        // Display recommendations
        this.displayRecommendations(result.recommendations);
        
        // Display analysis details
        this.displayAnalysisDetails(result.analysis_details);
        
        // Display technical details
        this.displayTechnicalDetails(result);
        
        // Scroll to results
        this.resultsContainer.scrollIntoView({ behavior: 'smooth' });
    }
    
    updateConfidenceBar(confidence) {
        const confidenceBar = document.getElementById('confidenceBar');
        const confidenceText = document.getElementById('confidenceText');
        
        const percentage = Math.round(confidence * 100);
        confidenceBar.style.width = `${percentage}%`;
        confidenceText.textContent = `${percentage}% confidence`;
        
        // Set color based on confidence level with modern gradients
        if (percentage >= 80) {
            confidenceBar.className = 'progress-bar gradient-bg-success';
            confidenceBar.style.background = 'linear-gradient(45deg, #198754, #20c997)';
        } else if (percentage >= 60) {
            confidenceBar.className = 'progress-bar gradient-bg-warning';
            confidenceBar.style.background = 'linear-gradient(45deg, #ffc107, #fd7e14)';
        } else {
            confidenceBar.className = 'progress-bar gradient-bg-danger';
            confidenceBar.style.background = 'linear-gradient(45deg, #dc3545, #fd7e14)';
        }
    }
    
    displayRecommendations(recommendations) {
        const recommendationsList = document.getElementById('recommendationsList');
        recommendationsList.innerHTML = '';
        
        recommendations.forEach((recommendation, index) => {
            const li = document.createElement('li');
            li.className = 'recommendation-item';
            li.style.animationDelay = `${index * 0.1}s`;
            li.innerHTML = `<i class="fas fa-lightbulb me-2 text-warning"></i>${recommendation}`;
            recommendationsList.appendChild(li);
        });
    }
    
    displayAnalysisDetails(details) {
        const analysisDetails = document.getElementById('analysisDetails');
        analysisDetails.innerHTML = '';
        
        // Create feature cards
        const features = details.features || {};
        
        // Domain info
        if (details.domain) {
            this.addAnalysisFeature(analysisDetails, 'Domain', details.domain, 'info');
        }
        
        // Protocol
        if (details.protocol) {
            const isSecure = details.protocol === 'https';
            this.addAnalysisFeature(
                analysisDetails, 
                'Protocol', 
                details.protocol.toUpperCase(),
                isSecure ? 'success' : 'warning'
            );
        }
        
        // URL Length
        if (details.path_length !== undefined) {
            const isLong = details.path_length > 50;
            this.addAnalysisFeature(
                analysisDetails,
                'Path Length',
                `${details.path_length} characters`,
                isLong ? 'warning' : 'success'
            );
        }
        
        // Display detected issues
        Object.entries(features).forEach(([key, value]) => {
            if (typeof value === 'string' && value.length > 0) {
                this.addAnalysisFeature(analysisDetails, this.formatFeatureName(key), value, 'danger');
            }
        });
        
        // Risk scores
        this.addAnalysisFeature(
            analysisDetails,
            'Heuristic Score',
            `${Math.round(details.heuristic_score * 100)}%`,
            details.heuristic_score > 0.5 ? 'danger' : 'success'
        );
        
        this.addAnalysisFeature(
            analysisDetails,
            'ML Score',
            `${Math.round(details.ml_score * 100)}%`,
            details.ml_score > 0.5 ? 'danger' : 'success'
        );
    }
    
    addAnalysisFeature(container, title, content, type = 'info') {
        const col = document.createElement('div');
        col.className = 'col-md-6 mb-3';
        
        const featureDiv = document.createElement('div');
        featureDiv.className = `analysis-feature ${type}`;
        
        featureDiv.innerHTML = `
            <h6 class="mb-2">
                <i class="fas fa-${this.getIconForType(type)} me-2"></i>
                ${title}
            </h6>
            <p class="mb-0">${content}</p>
        `;
        
        col.appendChild(featureDiv);
        container.appendChild(col);
    }
    
    getIconForType(type) {
        switch (type) {
            case 'success': return 'check-circle';
            case 'warning': return 'exclamation-triangle';
            case 'danger': return 'times-circle';
            default: return 'info-circle';
        }
    }
    
    formatFeatureName(key) {
        return key.replace(/_/g, ' ')
                 .replace(/\b\w/g, l => l.toUpperCase());
    }
    
    displayTechnicalDetails(result) {
        const technicalDetailsContent = document.getElementById('technicalDetailsContent');
        
        const technicalData = {
            'Analysis ID': result.id,
            'URL': result.url,
            'Risk Level': result.risk_level,
            'Confidence Score': result.confidence_score,
            'Timestamp': result.timestamp,
            'Detailed Analysis': result.analysis_details
        };
        
        technicalDetailsContent.textContent = JSON.stringify(technicalData, null, 2);
    }
    
    async loadStats() {
        try {
            const response = await fetch('/api/stats');
            const stats = await response.json();
            
            if (response.ok) {
                document.getElementById('totalAnalyses').textContent = stats.total_analyses.toLocaleString();
                document.getElementById('phishingDetected').textContent = stats.phishing_detected.toLocaleString();
                document.getElementById('safeUrls').textContent = stats.safe_urls.toLocaleString();
                document.getElementById('phishingPercentage').textContent = `${stats.phishing_percentage}%`;
            }
        } catch (error) {
            console.error('Failed to load statistics:', error);
        }
    }
    
    setLoading(loading) {
        if (loading) {
            this.analyzeBtn.disabled = true;
            this.loadingSpinner.classList.remove('d-none');
            this.searchIcon.classList.add('d-none');
            this.analyzeBtn.classList.add('loading');
        } else {
            this.analyzeBtn.disabled = false;
            this.loadingSpinner.classList.add('d-none');
            this.searchIcon.classList.remove('d-none');
            this.analyzeBtn.classList.remove('loading');
        }
    }
    
    showError(message) {
        this.errorMessage.textContent = message;
        this.errorAlert.classList.remove('d-none');
        this.errorAlert.scrollIntoView({ behavior: 'smooth' });
    }
    
    hideError() {
        this.errorAlert.classList.add('d-none');
    }
    
    isValidURL(string) {
        try {
            let url = string.trim();
            
            // Basic validation: must not be empty and not contain spaces
            if (!url || /\s/.test(url)) {
                return false;
            }
            
            // If it has a protocol, validate as-is
            if (url.match(/^https?:\/\//)) {
                const urlObj = new URL(url);
                return urlObj.hostname.length > 0;
            }
            
            // For URLs without protocol, be more permissive
            // Accept anything that looks like domain/path or localhost
            if (url === 'localhost' || url.startsWith('localhost/')) {
                return true;
            }
            
            // Must have at least one dot for domain, but can have paths
            if (!url.includes('.')) {
                return false;
            }
            
            // Split by / to get domain part
            const parts = url.split('/');
            const domain = parts[0];
            
            // Basic domain validation - must have valid characters and at least one dot
            const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/;
            return domainRegex.test(domain) && domain.includes('.');
        } catch (_) {
            return false;
        }
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new PhishingDetector();
});

// Additional utility functions
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Show success message (could implement toast notifications)
        console.log('Copied to clipboard:', text);
    });
}

function formatTimestamp(isoString) {
    return new Date(isoString).toLocaleString();
}

// Export for potential module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PhishingDetector;
}
