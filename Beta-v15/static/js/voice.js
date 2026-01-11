class AISearchEngine {
    constructor() {
        this.isSearching = false;
        this.isListening = false;
        this.recognition = null;
        this.initElements();
        this.initVoice();
        this.bindEvents();
    }
    
    initElements() {
        this.toggleBtn = document.getElementById('search-toggle');
        this.panel = document.getElementById('search-panel');
        this.input = document.getElementById('search-input');
        this.searchBtn = document.getElementById('search-btn');
        this.resultsContainer = document.getElementById('search-results');
        
        // Add voice button to the panel if it doesn't exist
        if (this.panel && !document.getElementById('voice-search-btn')) {
            const voiceBtn = document.createElement('button');
            voiceBtn.id = 'voice-search-btn';
            voiceBtn.className = 'btn btn-outline-secondary ms-2';
            voiceBtn.innerHTML = '<i class="fas fa-microphone"></i>';
            voiceBtn.title = 'Speak your query';
            
            // Insert after search button
            if (this.searchBtn) {
                this.searchBtn.parentNode.insertBefore(voiceBtn, this.searchBtn.nextSibling);
                this.voiceBtn = voiceBtn;
            }
        } else {
            this.voiceBtn = document.getElementById('voice-search-btn');
        }
    }
    
    initVoice() {
        const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
        if (SpeechRecognition) {
            this.recognition = new SpeechRecognition();
            this.recognition.continuous = false;
            this.recognition.interimResults = false;
            this.recognition.lang = 'en-US'; // Default, but supports multiple
            
            this.recognition.onstart = () => {
                this.isListening = true;
                if (this.voiceBtn) {
                    this.voiceBtn.classList.add('btn-danger');
                    this.voiceBtn.classList.remove('btn-outline-secondary');
                    this.voiceBtn.innerHTML = '<i class="fas fa-stop"></i>';
                }
                if (this.input) this.input.placeholder = "Listening...";
            };
            
            this.recognition.onresult = (event) => {
                const transcript = event.results[0][0].transcript;
                if (this.input) {
                    this.input.value = transcript;
                    this.search(transcript);
                }
            };
            
            this.recognition.onend = () => {
                this.isListening = false;
                if (this.voiceBtn) {
                    this.voiceBtn.classList.remove('btn-danger');
                    this.voiceBtn.classList.add('btn-outline-secondary');
                    this.voiceBtn.innerHTML = '<i class="fas fa-microphone"></i>';
                }
                if (this.input) this.input.placeholder = "Search for alerts (e.g., 'show me umair.farooq alerts')...";
            };
            
            this.recognition.onerror = (event) => {
                console.error('Speech recognition error:', event.error);
                this.stopListening();
            };
        }
    }
    
    bindEvents() {
        if (this.toggleBtn) {
            this.toggleBtn.addEventListener('click', () => this.toggle());
        }
        
        if (this.searchBtn) {
            this.searchBtn.addEventListener('click', () => {
                const query = this.input.value.trim();
                if (query) {
                    this.search(query);
                }
            });
        }
        
        if (this.voiceBtn) {
            this.voiceBtn.addEventListener('click', () => {
                if (this.isListening) {
                    this.stopListening();
                } else {
                    this.startListening();
                }
            });
        }
        
        if (this.input) {
            this.input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    const query = this.input.value.trim();
                    if (query) {
                        this.search(query);
                    }
                }
            });
        }
    }
    
    startListening() {
        if (this.recognition) {
            try {
                this.recognition.start();
            } catch (e) {
                console.error('Failed to start recognition:', e);
            }
        } else {
            alert('Speech recognition is not supported in this browser.');
        }
    }
    
    stopListening() {
        if (this.recognition) {
            this.recognition.stop();
        }
    }
    
    toggle() {
        if (this.panel) {
            this.panel.classList.toggle('show');
            this.toggleBtn.classList.toggle('active');
            
            if (this.panel.classList.contains('show')) {
                this.input.focus();
            }
        }
    }
    
    async search(query) {
        if (this.isSearching) return;
        
        this.isSearching = true;
        this.showLoading();
        
        try {
            const response = await fetch('/api/insights/voice-qa', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    question: query,
                    include_context: true,
                    model_type: 'openai'
                })
            });
            
            const result = await response.json();
            this.isSearching = false;
            
            if (result.error) {
                this.displayError(result.error);
            } else if (result.success && result.answer) {
                this.displayResult(query, result.answer, result.summary);
                
                // If the answer suggests an action or process, we can trigger specific UI updates
                this.processExecution(query, result);
            } else {
                this.displayError('Unable to process your search. Please try again.');
            }
        } catch (error) {
            console.error('Search error:', error);
            this.isSearching = false;
            this.displayError('Search failed. Please check your connection and try again.');
        }
    }
    
    processExecution(query, result) {
        // Auto-navigate or trigger actions based on query intent
        const lowerQuery = query.toLowerCase();
        
        if (lowerQuery.includes('dashboard') || lowerQuery.includes('summary')) {
            // Potentially refresh dashboard stats if on the dashboard page
            if (window.location.pathname === '/' || window.location.pathname === '/dashboard') {
                console.log('Voice triggered dashboard refresh');
                if (typeof loadDashboardStats === 'function') loadDashboardStats();
            }
        }
        
        if (lowerQuery.includes('alert') && (lowerQuery.includes('show') || lowerQuery.includes('list'))) {
            // If on alerts page, apply filter
            if (window.location.pathname.includes('/alerts')) {
                const searchInput = document.querySelector('input[type="search"]');
                if (searchInput) {
                    searchInput.value = query;
                    searchInput.dispatchEvent(new Event('input'));
                }
            }
        }
        
        // Add more process executions here based on user intent
    }
    
    showLoading() {
        this.resultsContainer.innerHTML = `
            <div class="search-loading">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Searching...</span>
                </div>
                <span class="text-muted">Analyzing your security data...</span>
            </div>
        `;
    }
    
    displayResult(query, answer, summary) {
        const formattedAnswer = this.formatText(answer);
        
        let html = `
            <div class="search-result-item">
                <div class="search-result-title">
                    <i class="fas fa-comment me-2" style="color: #48bb78;"></i>
                    Processed Query
                </div>
                <div class="search-result-content">
                    <strong>${this.escapeHtml(query)}</strong>
                </div>
            </div>
        `;
        
        if (summary) {
            html += `
                <div class="search-result-item">
                    <div class="search-result-title">
                        <i class="fas fa-bolt me-2" style="color: #f6ad55;"></i>
                        AI Insight
                    </div>
                    <div class="search-result-content">
                        ${this.escapeHtml(summary)}
                    </div>
                </div>
            `;
        }
        
        html += `
            <div class="search-result-item">
                <div class="search-result-title">
                    <i class="fas fa-shield-alt me-2" style="color: #667eea;"></i>
                    Security Analysis
                </div>
                <div class="search-result-content">
                    ${formattedAnswer}
                </div>
            </div>
        `;
        
        this.resultsContainer.innerHTML = html;
        this.resultsContainer.scrollTop = 0;
    }
    
    displayError(errorMessage) {
        this.resultsContainer.innerHTML = `
            <div class="search-result-item" style="border-left-color: #f56565;">
                <div class="search-result-title" style="color: #f56565;">
                    <i class="fas fa-exclamation-circle me-2"></i>
                    Error
                </div>
                <div class="search-result-content">
                    ${this.escapeHtml(errorMessage)}
                </div>
            </div>
        `;
    }
    
    formatText(text) {
        if (!text) return '';
        
        let formatted = this.escapeHtml(text);
        
        // Convert markdown-like formatting
        formatted = formatted
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code style="background: #2d3748; padding: 2px 6px; border-radius: 3px;">$1</code>')
            .replace(/\n\n/g, '</p><p>')
            .replace(/\n/g, '<br>');
        
        // Add paragraph tags
        formatted = `<p>${formatted}</p>`;
        
        return formatted;
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

let searchEngine = null;

function toggleSearch() {
    if (searchEngine) {
        searchEngine.toggle();
    }
}

document.addEventListener('DOMContentLoaded', function() {
    const searchToggle = document.getElementById('search-toggle');
    
    if (searchToggle) {
        searchEngine = new AISearchEngine();
    }
});
