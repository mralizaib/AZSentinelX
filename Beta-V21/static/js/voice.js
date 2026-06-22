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
        this.toggleBtn       = document.getElementById('search-toggle');
        this.panel           = document.getElementById('search-panel');
        this.input           = document.getElementById('search-input');
        this.searchBtn       = document.getElementById('search-btn');
        this.resultsContainer = document.getElementById('search-results');

        if (this.panel && !document.getElementById('voice-search-btn')) {
            const voiceBtn = document.createElement('button');
            voiceBtn.id        = 'voice-search-btn';
            voiceBtn.className = 'btn btn-outline-secondary ms-2';
            voiceBtn.innerHTML = '<i class="fas fa-microphone"></i>';
            voiceBtn.title     = 'Speak your query';
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
            this.recognition.continuous    = false;
            this.recognition.interimResults = false;
            this.recognition.lang          = 'en-US';

            this.recognition.onstart = () => {
                this.isListening = true;
                if (this.voiceBtn) {
                    this.voiceBtn.classList.add('btn-danger');
                    this.voiceBtn.classList.remove('btn-outline-secondary');
                    this.voiceBtn.innerHTML = '<i class="fas fa-stop"></i>';
                }
                if (this.input) this.input.placeholder = 'Listening...';
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
                if (this.input) this.input.placeholder = 'Search alerts, systems, users, IPs...';
            };

            this.recognition.onerror = (event) => {
                console.error('Speech recognition error:', event.error);
                this.stopListening();
            };
        }
    }

    bindEvents() {
        if (this.toggleBtn) this.toggleBtn.addEventListener('click', () => this.toggle());

        if (this.searchBtn) {
            this.searchBtn.addEventListener('click', () => {
                const q = this.input.value.trim();
                if (q) this.search(q);
            });
        }

        if (this.voiceBtn) {
            this.voiceBtn.addEventListener('click', () => {
                this.isListening ? this.stopListening() : this.startListening();
            });
        }

        if (this.input) {
            this.input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    const q = this.input.value.trim();
                    if (q) this.search(q);
                }
            });
        }
    }

    startListening() {
        if (this.recognition) {
            try { this.recognition.start(); } catch (e) { console.error(e); }
        } else {
            alert('Speech recognition is not supported in this browser.');
        }
    }

    stopListening() {
        if (this.recognition) this.recognition.stop();
    }

    toggle() {
        if (this.panel) {
            this.panel.classList.toggle('show');
            this.toggleBtn.classList.toggle('active');
            if (this.panel.classList.contains('show')) this.input.focus();
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
                body: JSON.stringify({ question: query, include_context: true, model_type: 'openai' })
            });
            const result = await response.json();
            this.isSearching = false;

            if (result.error) {
                this.displayError(result.error);
            } else if (result.success) {
                this.displayResult(query, result);
            } else {
                this.displayError('Unable to process your search. Please try again.');
            }
        } catch (error) {
            console.error('Search error:', error);
            this.isSearching = false;
            this.displayError('Search failed. Please check your connection and try again.');
        }
    }

    /* ── helpers ─────────────────────────────────────────── */

    severityMeta(sev) {
        const map = {
            critical: { color: '#fc8181', bg: 'rgba(252,129,129,0.15)', badge: '#9b2335', label: 'Critical' },
            high:     { color: '#f6ad55', bg: 'rgba(246,173,85,0.15)',  badge: '#b7490a', label: 'High'     },
            medium:   { color: '#f6e05e', bg: 'rgba(246,224,94,0.15)',  badge: '#8a6a00', label: 'Medium'   },
            low:      { color: '#68d391', bg: 'rgba(104,211,145,0.15)', badge: '#276749', label: 'Low'      },
        };
        return map[sev] || map.low;
    }

    formatDate(dateStr) {
        if (!dateStr) return 'N/A';
        try {
            return new Date(dateStr).toLocaleString(undefined, {
                year: 'numeric', month: 'short', day: 'numeric',
                hour: '2-digit', minute: '2-digit', second: '2-digit'
            });
        } catch (e) { return dateStr; }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    formatAnswer(text) {
        if (!text) return '';
        let out = this.escapeHtml(text);
        out = out
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code style="background:#2d3748;padding:2px 6px;border-radius:3px;font-size:12px;">$1</code>')
            .replace(/\n{2,}/g, '</p><p style="margin-bottom:6px;">')
            .replace(/\n/g, '<br>');
        return `<p style="margin-bottom:6px;">${out}</p>`;
    }

    /* ── display states ──────────────────────────────────── */

    showLoading() {
        this.resultsContainer.innerHTML = `
            <div class="search-loading">
                <div class="spinner-border text-primary" role="status" style="width:1.5rem;height:1.5rem;">
                    <span class="visually-hidden">Loading…</span>
                </div>
                <span class="text-muted ms-2" style="font-size:13px;">Searching security data…</span>
            </div>`;
    }

    displayError(msg) {
        this.resultsContainer.innerHTML = `
            <div class="search-result-item" style="border-left-color:#f56565;">
                <div class="search-result-title" style="color:#f56565;">
                    <i class="fas fa-exclamation-circle me-2"></i>Error
                </div>
                <div class="search-result-content">${this.escapeHtml(msg)}</div>
            </div>`;
    }

    displayResult(query, result) {
        const alerts      = result.alerts      || [];
        const total       = result.total_alerts || 0;
        const answer      = result.answer       || '';
        const summary     = result.summary      || '';

        let html = '';

        /* ── AI Analysis card ── */
        if (answer) {
            html += `
            <div class="search-result-item" style="border-left-color:#667eea;">
                <div class="search-result-title">
                    <i class="fas fa-robot me-2" style="color:#667eea;"></i>AI Analysis
                </div>
                <div class="search-result-content" style="font-size:13px;line-height:1.6;">
                    ${this.formatAnswer(answer)}
                </div>
            </div>`;
        }

        /* ── Alert records table ── */
        if (alerts.length > 0) {
            const showing = alerts.length;
            const more    = total > showing ? ` — <em>${total.toLocaleString()} total matching</em>` : '';

            /* Build table rows */
            let rows = '';
            for (const a of alerts) {
                const meta      = this.severityMeta(a.severity);
                const ts        = this.formatDate(a.timestamp);
                const desc      = this.escapeHtml(a.rule_desc);
                const agent     = this.escapeHtml(a.agent_name);
                const ip        = this.escapeHtml(a.agent_ip);
                const ruleId    = this.escapeHtml(String(a.rule_id));
                const viewHref  = a.id
                    ? `/alerts/view/${encodeURIComponent(a.id)}?index=${encodeURIComponent(a.index)}`
                    : '#';

                rows += `
                <tr style="border-bottom:1px solid #2d3748;">
                    <td style="padding:6px 8px;white-space:nowrap;">
                        <span style="
                            display:inline-block;padding:2px 7px;border-radius:4px;
                            font-size:11px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;
                            background:${meta.badge};color:#fff;">
                            ${meta.label}
                        </span>
                    </td>
                    <td style="padding:6px 8px;font-size:11px;color:#a0aec0;white-space:nowrap;">${ts}</td>
                    <td style="padding:6px 8px;font-size:12px;color:#e2e8f0;">
                        ${agent}<br><span style="color:#718096;font-size:11px;">${ip}</span>
                    </td>
                    <td style="padding:6px 8px;font-size:12px;color:#e2e8f0;max-width:200px;">
                        <span title="${desc}" style="display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:190px;">${desc}</span>
                        <span style="color:#718096;font-size:11px;">Rule ${ruleId}</span>
                    </td>
                    <td style="padding:6px 8px;text-align:center;">
                        ${viewHref !== '#' ? `<a href="${viewHref}" style="color:#667eea;font-size:12px;" title="View alert details"><i class="fas fa-external-link-alt"></i></a>` : ''}
                    </td>
                </tr>`;
            }

            html += `
            <div class="search-result-item" style="border-left-color:#48bb78;padding:0;">
                <div style="padding:10px 12px 6px;display:flex;justify-content:space-between;align-items:center;">
                    <span class="search-result-title" style="margin:0;">
                        <i class="fas fa-table me-2" style="color:#48bb78;"></i>
                        Alert Results <span style="font-weight:400;color:#a0aec0;font-size:12px;">(${showing} shown${more})</span>
                    </span>
                    <a href="/alerts" style="font-size:11px;color:#667eea;">Open Alerts Page <i class="fas fa-arrow-right"></i></a>
                </div>
                <div style="overflow-x:auto;">
                    <table style="width:100%;border-collapse:collapse;font-size:12px;">
                        <thead>
                            <tr style="background:#0f0f23;color:#718096;font-size:11px;text-transform:uppercase;letter-spacing:.5px;">
                                <th style="padding:6px 8px;font-weight:600;">Severity</th>
                                <th style="padding:6px 8px;font-weight:600;">Timestamp</th>
                                <th style="padding:6px 8px;font-weight:600;">Agent</th>
                                <th style="padding:6px 8px;font-weight:600;">Description</th>
                                <th style="padding:6px 8px;font-weight:600;"></th>
                            </tr>
                        </thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>
            </div>`;
        } else if (!answer) {
            html += `
            <div class="search-result-item" style="border-left-color:#718096;">
                <div class="search-result-content" style="color:#a0aec0;font-size:13px;">
                    No alerts found matching your query.
                </div>
            </div>`;
        }

        this.resultsContainer.innerHTML = html;
        this.resultsContainer.scrollTop = 0;
    }
}

/* ── bootstrap ───────────────────────────────────────────── */
let searchEngine = null;

function toggleSearch() {
    if (searchEngine) searchEngine.toggle();
}

document.addEventListener('DOMContentLoaded', function () {
    if (document.getElementById('search-toggle')) {
        searchEngine = new AISearchEngine();
    }
});
