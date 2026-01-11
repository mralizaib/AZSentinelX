/**
 * Dashboard JavaScript - AZ Sentinel X
 * Handles dashboard functionality, charts, and data loading
 */

document.addEventListener('DOMContentLoaded', function() {
    // Check if we are on the dashboard page before initializing
    if (!document.getElementById('alerts-timeline-chart')) {
        console.log('Not on dashboard page, skipping initialization');
        return;
    }

    // Load initial dashboard data
    loadDashboardStatsForTimeRange(1);
    loadAlertsTimeline(1);
    loadTopRules(1);
    loadThreatAnalysis();

    // Set up event listeners for time range buttons
    document.querySelectorAll('.timeline-range').forEach(item => {
        item.addEventListener('click', function() {
            const days = this.getAttribute('data-days');
            document.querySelectorAll('.timeline-range').forEach(el => el.classList.remove('active'));
            this.classList.add('active');
            loadDashboardStatsForTimeRange(days);
            loadAlertsTimeline(days);
            loadTopRules(days);
        });
    });

    // Delegated event listener for clickable elements to prevent hanging issues
    document.body.addEventListener('click', function(e) {
        // Handle severity cards
        const card = e.target.closest('.clickable-card');
        if (card) {
            const severity = card.getAttribute('data-severity');
            window.location.href = `/alerts?severity=${severity}`;
            return;
        }
        
        // Handle agent status cards
        const agentCard = e.target.closest('.agent-status-card');
        if (agentCard) {
            const status = agentCard.getAttribute('data-status');
            showAgentDetails(status);
            return;
        }

        // Handle recent activity rows
        const activityRow = e.target.closest('.recent-activity-row');
        if (activityRow) {
            const alertId = activityRow.getAttribute('data-alert-id');
            window.location.href = `/alerts/view/${alertId}`;
            return;
        }

        // Handle top rules rows
        const ruleRow = e.target.closest('.top-rule-row');
        if (ruleRow) {
            const ruleId = ruleRow.getAttribute('data-rule-id');
            // Search for alerts with this rule ID to allow viewing them
            window.location.href = `/alerts?search=${ruleId}`;
            return;
        }
    });

    // Agent search filter
    const agentSearchInput = document.getElementById('agent-search-filter');
    if (agentSearchInput) {
        agentSearchInput.addEventListener('input', function() {
            filterAgentTable(this.value);
        });
    }

    // Export agents to Excel
    const exportAgentsBtn = document.getElementById('export-agents-xlsx');
    if (exportAgentsBtn) {
        exportAgentsBtn.addEventListener('click', function() {
            exportAgentsToExcel();
        });
    }

    // Refresh button
    const refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            const activeRange = document.querySelector('.timeline-range.active');
            const days = activeRange ? activeRange.getAttribute('data-days') : 1;
            loadDashboardStatsForTimeRange(days);
            loadAlertsTimeline(days);
            loadTopRules(days);
            loadThreatAnalysis();
        });
    }
});

// Using a module-level variable to store current modal instance to prevent multiple instances
if (typeof agentDetailsModal === 'undefined') {
    window.agentDetailsModal = null;
}

function loadDashboardStatsForTimeRange(days = 1) {
    fetch(`/api/dashboard/stats?days=${days}`)
        .then(response => response.json())
        .then(data => {
            updateAlertCountCards(data.alert_counts);
            updateAgentCards(data.agent_stats);
            updateRecentAlerts(data.recent_alerts);
        })
        .catch(error => console.error('Error loading dashboard stats:', error));
}

function updateAlertCountCards(alertCounts) {
    if (!alertCounts) return;
    const mapping = {
        'critical-count': 'critical',
        'high-count': 'high',
        'medium-count': 'medium',
        'low-count': 'low',
        'events-count': 'events'
    };
    Object.keys(mapping).forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = alertCounts[mapping[id]] || 0;
    });
}

function updateAgentCards(agentStats) {
    if (!agentStats) return;
    const mapping = {
        'total-agents': 'total',
        'active-agents': 'active',
        'disconnected-agents': 'disconnected'
    };
    Object.keys(mapping).forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = agentStats[mapping[id]] || 0;
    });
}

function updateRecentAlerts(alerts) {
    const tableBody = document.getElementById('recent-alerts-body');
    if (!tableBody || !alerts) return;
    tableBody.innerHTML = alerts.length === 0 ? '<tr><td class="text-center py-5 text-muted">No recent activity</td></tr>' : '';
    alerts.forEach(alert => {
        const source = alert.source;
        if (!source) return;
        const row = document.createElement('tr');
        row.className = 'recent-activity-row clickable-row';
        row.style.cursor = 'pointer';
        row.setAttribute('data-alert-id', alert.id || '');
        row.innerHTML = `
            <td class="ps-4 py-3">
                <div class="d-flex justify-content-between mb-1">
                    <span class="small text-muted">${new Date(source['@timestamp']).toLocaleString()}</span>
                    <span class="badge ${getSeverityClass(source.rule?.level)}">${source.rule?.level || 0}</span>
                </div>
                <div class="fw-bold text-light">${source.rule?.description || 'N/A'}</div>
                <div class="small text-muted">Agent: ${source.agent?.name || 'N/A'}</div>
            </td>
        `;
        tableBody.appendChild(row);
    });
}

function getSeverityClass(level) {
    if (level >= 12) return 'bg-danger';
    if (level >= 7) return 'bg-warning text-dark';
    return 'bg-secondary';
}

function loadTopRules(days = 1) {
    const tableBody = document.getElementById('top-rules-body');
    if (!tableBody) return;
    fetch(`/api/dashboard/top_rules?days=${days}`)
        .then(response => response.json())
        .then(rules => {
            tableBody.innerHTML = rules.length === 0 ? '<tr><td class="text-center py-5 text-muted">No data</td></tr>' : '';
            rules.forEach(rule => {
                const row = document.createElement('tr');
                row.className = 'top-rule-row clickable-row';
                row.style.cursor = 'pointer';
                row.setAttribute('data-rule-id', rule.rule_id);
                row.innerHTML = `
                    <td class="ps-4 py-3">
                        <div class="d-flex justify-content-between align-items-center">
                            <div class="fw-bold text-light">${rule.description}</div>
                            <span class="badge bg-primary rounded-pill">${rule.count}</span>
                        </div>
                        <div class="small text-muted">Rule ID: ${rule.rule_id} | Level: ${rule.level}</div>
                    </td>
                `;
                tableBody.appendChild(row);
            });
        });
}

function showAgentDetails(status = 'all') {
    const modalEl = document.getElementById('agent-details-modal');
    if (!modalEl) return;
    
    // Dispose previous modal instance if it exists to prevent hanging/leaks
    let modalInstance = bootstrap.Modal.getInstance(modalEl);
    if (modalInstance) {
        modalInstance.hide();
        // Give it a small timeout to finish hiding before disposing
        setTimeout(() => {
            modalInstance.dispose();
            initializeAndShowModal();
        }, 150);
    } else {
        initializeAndShowModal();
    }
    
    function initializeAndShowModal() {
        // Dispose any existing backdrop that might be stuck
        const existingBackdrops = document.querySelectorAll('.modal-backdrop');
        existingBackdrops.forEach(backdrop => backdrop.remove());
        document.body.classList.remove('modal-open');
        document.body.style.overflow = '';
        document.body.style.paddingRight = '';

        agentDetailsModal = new bootstrap.Modal(modalEl);
        const tableBody = document.getElementById('agent-details-table-body');
        const modalTitle = document.getElementById('agent-modal-title');
        
        const titles = { 'all': 'Total Agents', 'active': 'Active Agents', 'disconnected': 'Disconnected Agents' };
        modalTitle.textContent = titles[status] || 'Agent Details';
        tableBody.innerHTML = '<tr><td colspan="8" class="text-center py-5"><div class="spinner-border text-primary"></div></td></tr>';
        agentDetailsModal.show();

        fetch(`/api/dashboard/agents?status=${status}`)
            .then(response => response.json())
            .then(agents => {
                window.currentAgents = agents;
                renderAgentTable(agents);
            })
            .catch(err => {
                tableBody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-5">Error: ${err.message}</td></tr>`;
            });
    }
}

function renderAgentTable(agents) {
    const tableBody = document.getElementById('agent-details-table-body');
    if (!tableBody) return;
    tableBody.innerHTML = agents.length === 0 ? '<tr><td colspan="8" class="text-center py-5 text-muted">No agents found</td></tr>' : '';
    agents.forEach(agent => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${agent.id}</td>
            <td>${agent.name}</td>
            <td>${agent.ip || 'N/A'}</td>
            <td><span class="badge ${agent.status === 'active' ? 'bg-success' : 'bg-danger'}">${agent.status}</span></td>
            <td>${agent.group || 'default'}</td>
            <td>${agent.location || 'N/A'}</td>
            <td>${agent.os?.name || 'N/A'}</td>
            <td>${agent.lastKeepAlive || 'N/A'}</td>
        `;
        tableBody.appendChild(row);
    });
}

function filterAgentTable(query) {
    if (!window.currentAgents) return;
    const q = query.toLowerCase();
    const filtered = window.currentAgents.filter(a => 
        a.name.toLowerCase().includes(q) || 
        (a.ip && a.ip.includes(q)) ||
        (a.id && a.id.includes(q))
    );
    renderAgentTable(filtered);
}

function exportAgentsToExcel() {
    if (!window.currentAgents) return;
    let csv = 'ID,Name,IP,Status,OS\n' + window.currentAgents.map(a => 
        `"${a.id}","${a.name}","${a.ip || ''}","${a.status}","${a.os?.name || ''}"`
    ).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'agents_export.csv';
    a.click();
}

function loadAlertsTimeline(days) {
    const container = document.getElementById('alerts-timeline-chart');
    if (!container) return;
    fetch(`/api/dashboard/alerts_timeline?days=${days}`)
        .then(response => response.json())
        .then(data => renderTimelineChart(data, container))
        .catch(err => console.error('Timeline error:', err));
}

function renderTimelineChart(data, container) {
    container.innerHTML = '<canvas></canvas>';
    const ctx = container.querySelector('canvas').getContext('2d');
    if (!data || data.length === 0) {
        container.innerHTML = '<div class="text-center py-5 text-muted">No timeline data</div>';
        return;
    }
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(d => new Date(d.timestamp).toLocaleTimeString()),
            datasets: [{
                label: 'Total Alerts',
                data: data.map(d => d.total),
                borderColor: '#3b82f6',
                tension: 0.3,
                fill: true,
                backgroundColor: 'rgba(59, 130, 246, 0.1)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false }, ticks: { color: '#64748b' } },
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#64748b' } }
            }
        }
    });
}

function loadThreatAnalysis() {
    const container = document.getElementById('locations-chart');
    if (!container) return;
    fetch('/api/dashboard/threat_analysis')
        .then(response => response.json())
        .then(data => renderLocationsChart(data.locations, container))
        .catch(err => console.error('Threat analysis error:', err));
}

function renderLocationsChart(locations, container) {
    container.innerHTML = '<canvas></canvas>';
    const ctx = container.querySelector('canvas').getContext('2d');
    if (!locations || locations.length === 0) {
        container.innerHTML = '<div class="text-center py-5 text-muted">No location data</div>';
        return;
    }
    
    // Create random colors for potentially many locations
    const colors = locations.map((_, i) => {
        const hue = (i * 137.5) % 360;
        return `hsl(${hue}, 70%, 50%)`;
    });

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: locations.map(l => l.name),
            datasets: [{
                data: locations.map(l => l.count),
                backgroundColor: colors,
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { 
                    position: 'bottom', 
                    labels: { 
                        color: '#94a3b8', 
                        padding: 10, 
                        boxWidth: 8,
                        font: { size: 10 }
                    } 
                }
            },
            cutout: '60%'
        }
    });
}
