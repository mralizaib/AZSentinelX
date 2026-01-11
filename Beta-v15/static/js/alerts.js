/**
 * Alerts JavaScript - AZ Sentinel X
 * Handles security alerts fetching, filtering, and alert configuration
 */

document.addEventListener('DOMContentLoaded', function() {
    // Load alert configurations
    loadAlertConfigs();

    // Check for severity filter in URL
    const urlParams = new URLSearchParams(window.location.search);
    const severityParam = urlParams.get('severity');
    
    if (severityParam) {
        // Set only the requested severity
        document.querySelectorAll('input[name="severity-filter"]').forEach(cb => {
            cb.checked = (cb.value === severityParam.toLowerCase());
        });
    } else {
        // Default: check Critical and High if no specific filter
        const criticalCb = document.getElementById('filter-critical');
        const highCb = document.getElementById('filter-high');
        if (criticalCb) criticalCb.checked = true;
        if (highCb) highCb.checked = true;
    }

    // Load security alerts with default or URL filters
    loadSecurityAlerts();

    // Set up filter form event listener
    const filterForm = document.getElementById('alert-filter-form');
    if (filterForm) {
        filterForm.addEventListener('submit', function(event) {
            event.preventDefault();
            loadSecurityAlerts();
        });
    }

    // Set up refresh button
    const refreshBtn = document.getElementById('refresh-alerts-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadSecurityAlerts();
        });
    }

    // Set up create alert form
    const createAlertForm = document.getElementById('create-alert-form');
    if (createAlertForm) {
        createAlertForm.addEventListener('submit', handleCreateAlert);
    }

    // Set up export buttons
    const exportCsvBtn = document.getElementById('export-csv');
    const exportXlsxBtn = document.getElementById('export-xlsx');
    const exportPdfBtn = document.getElementById('export-pdf');

    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', function(e) {
            e.preventDefault();
            exportAlerts('csv');
        });
    }

    if (exportXlsxBtn) {
        exportXlsxBtn.addEventListener('click', function(e) {
            e.preventDefault();
            exportAlerts('xlsx');
        });
    }

    if (exportPdfBtn) {
        exportPdfBtn.addEventListener('click', function(e) {
            e.preventDefault();
            exportAlerts('pdf');
        });
    }
});

// Global pagination state
let currentPage = 1;
let totalPages = 1;
const alertsPerPage = 50;

/**
 * Load security alerts from API based on filters
 */
function loadSecurityAlerts(page = 1) {
    const alertsContainer = document.getElementById('alerts-table-body');
    if (!alertsContainer) return;

    currentPage = page;

    // Show loading indicator
    alertsContainer.innerHTML = `
        <tr>
            <td colspan="6" class="text-center">
                <div class="d-flex justify-content-center">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                </div>
            </td>
        </tr>
    `;

    // Get filter values
    const severityLevels = [];
    document.querySelectorAll('input[name="severity-filter"]:checked').forEach(checkbox => {
        severityLevels.push(checkbox.value);
    });

    const timeRange = document.getElementById('time-range-filter').value;

    // Build query parameters
    const params = new URLSearchParams();
    severityLevels.forEach(level => {
        params.append('severity_levels[]', level);
    });
    params.append('time_range', timeRange);

    // Add pagination parameters
    params.append('limit', alertsPerPage);
    params.append('offset', (currentPage - 1) * alertsPerPage);

    // Additional filters
    const searchQuery = document.getElementById('search-filter')?.value;
    if (searchQuery && searchQuery.trim()) {
        params.append('search_query', searchQuery.trim());
    }

    const ruleId = document.getElementById('rule-filter')?.value;
    if (ruleId) {
        params.append('rule_id', ruleId);
    }

    // Fetch alerts
    fetch(`/api/alerts?${params.toString()}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            displayAlerts(data, alertsContainer);

            // Update result count
            const resultCount = document.getElementById('alert-count');
            if (resultCount) {
                resultCount.textContent = data.total || 0;
            }

            // Calculate and display pagination
            totalPages = Math.ceil((data.total || 0) / alertsPerPage);
            displayPagination(data.total || 0);
        })
        .catch(error => {
            console.error('Error loading alerts:', error);
            alertsContainer.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center">
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            Error loading alerts: ${error.message}
                        </div>
                    </td>
                </tr>
            `;
        });
}

/**
 * Export alerts to CSV, XLSX, or PDF
 */
function exportAlerts(format) {
    if (!format) {
        alert('Please select a format to export.');
        return;
    }

    // Show loading indicator
    const exportBtn = document.querySelector(`#export-${format.toLowerCase()}`);
    if (exportBtn) {
        const originalText = exportBtn.innerHTML;
        exportBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Exporting...';
        exportBtn.disabled = true;

        // Reset button after 30 seconds
        setTimeout(() => {
            exportBtn.innerHTML = originalText;
            exportBtn.disabled = false;
        }, 30000);
    }

    // Get filter values
    const severityLevels = [];
    document.querySelectorAll('input[name="severity-filter"]:checked').forEach(checkbox => {
        severityLevels.push(checkbox.value);
    });

    const timeRange = document.getElementById('time-range-filter').value;

    // Build query parameters
    const params = new URLSearchParams();
    severityLevels.forEach(level => {
        params.append('severity_levels[]', level);
    });
    params.append('time_range', timeRange);
    params.append('format', format.toLowerCase());

    // Additional filters
    const searchQuery = document.getElementById('search-filter')?.value;
    if (searchQuery) {
        params.append('search_query', searchQuery);
    }

    const ruleId = document.getElementById('rule-filter')?.value;
    if (ruleId) {
        params.append('rule_id', ruleId);
    }

    // Use the export endpoint directly
    const exportUrl = `/api/alerts/export?${params.toString()}`;

    // Show a toast or notification to the user
    if (typeof showToast === 'function') {
        showToast('Preparing your export, please wait...', 'info');
    }

    // Create a temporary link to trigger download
    const link = document.createElement('a');
    link.href = exportUrl;
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    
    // Clean up
    setTimeout(() => {
        document.body.removeChild(link);
    }, 100);

    // Reset button
    if (exportBtn) {
        setTimeout(() => {
            exportBtn.innerHTML = originalText;
            exportBtn.disabled = false;
        }, 2000);
    }
}

/**
 * Export alerts data to CSV format and trigger download
 */
function exportToCSV(alerts) {
    const csvRows = [];

    // Headers
    const headers = Object.keys(alerts[0].source);
    csvRows.push(headers.join(','));

    // Data rows
    for (const alert of alerts) {
        const values = headers.map(header => {
            let value = alert.source[header];
            if (typeof value === 'object') {
                value = JSON.stringify(value);
            }
            return value;
        });
        csvRows.push(values.join(','));
    }

    // Create CSV content
    const csvContent = csvRows.join('\n');

    // Create a Blob object
    const blob = new Blob([csvContent], { type: 'text/csv' });

    // Create a link element
    const link = document.createElement('a');
    link.href = window.URL.createObjectURL(blob);
    link.download = 'alerts.csv';

    // Append the link to the document
    document.body.appendChild(link);

    // Trigger the download
    link.click();

    // Remove the link from the document
    document.body.removeChild(link);
}

/**
 * Display alerts in the table
 */
function displayAlerts(data, container) {
    // Clear container
    container.innerHTML = '';

    const results = data.results || [];

    if (results.length === 0) {
        container.innerHTML = `
            <tr>
                <td colspan="6" class="text-center">
                    <div class="alert alert-info">
                        No alerts found matching your criteria.
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    // Loop through alerts and create table rows
    results.forEach(alert => {
        const source = alert.source;
        if (!source) return;

        // Get values with fallbacks
        const timestamp = source['@timestamp'] || 'N/A';
        const ruleId = source.rule?.id || 'N/A';
        const level = source.rule?.level || 0;
        const description = source.rule?.description || 'N/A';
        const agentName = source.agent?.name || 'N/A';
        const agentId = source.agent?.id || 'N/A';

        // Determine severity class
        let severityClass = 'severity-low';
        let severityText = 'Low';

        // Check if it's a Misc Event (based on description or Rule ID)
        const desc = description.toLowerCase();
        const ruleIdInt = parseInt(ruleId);
        const miscRuleIds = [750, 60642, 752, 550, 60106];
        const isMiscEvent = miscRuleIds.includes(ruleIdInt) || 
                            desc.includes('sonicwall warning') || 
                            desc.includes('sonicwall error') || 
                            desc.includes('integrity checksum changed') || 
                            desc.includes('registry value integrity checksum changed');

        if (isMiscEvent) {
            severityClass = 'text-info';
            severityText = 'Event';
        } else if (level >= 15) {
            severityClass = 'severity-critical';
            severityText = 'Critical';
        } else if (level >= 12) {
            severityClass = 'severity-high';
            severityText = 'High';
        } else if (level >= 7) {
            severityClass = 'severity-medium';
            severityText = 'Medium';
        }

        // Format date nicely
        let formattedDate = timestamp;
        try {
            const date = new Date(timestamp);
            formattedDate = date.toLocaleString();
        } catch (e) {
            console.error('Error formatting date:', e);
        }

        // Get agent IP
        const agentIp = source.agent?.ip || 'N/A';

        // Create row
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${formattedDate}</td>
            <td>${agentName} (${agentId})<br><small class="text-muted">${agentIp}</small></td>
            <td>${ruleId}</td>
            <td class="${severityClass}">${severityText} (${level})</td>
            <td>${description}</td>
            <td>
                <button class="btn btn-sm btn-primary btn-view-details" data-id="${alert.id}" data-index="${alert.index}">
                    <i class="fas fa-search"></i> Details
                </button>
            </td>
        `;

        container.appendChild(row);
    });

    // Add event listeners for details buttons
    document.querySelectorAll('.btn-view-details').forEach(button => {
        button.addEventListener('click', function() {
            const alertId = this.getAttribute('data-id');
            const alertIndex = this.getAttribute('data-index');
            viewAlertDetails(alertId, alertIndex);
        });
    });
}

/**
 * View alert details in a modal
 */
function viewAlertDetails(alertId, alertIndex) {
    const detailsModal = document.getElementById('alert-details-modal');
    const detailsBody = document.getElementById('alert-details-body');
    const detailsLoader = document.getElementById('alert-details-loader');

    if (detailsLoader) {
        detailsLoader.style.display = 'block';
    }

    if (detailsBody) {
        detailsBody.innerHTML = '';
    }

    // Show the modal
    const modal = new bootstrap.Modal(detailsModal);
    modal.show();

    // Find alert in existing results if possible
    const alertsData = document.getElementById('alerts-data');
    if (alertsData && alertsData.hasAttribute('data-alerts')) {
        try {
            const alerts = JSON.parse(alertsData.getAttribute('data-alerts'));
            const alert = alerts.find(a => a.id === alertId && a.index === alertIndex);

            if (alert) {
                renderAlertDetails(alert, detailsBody);
                if (detailsLoader) {
                    detailsLoader.style.display = 'none';
                }
                return;
            }
        } catch (e) {
            console.error('Error parsing stored alerts:', e);
        }
    }

    // If we couldn't find the alert in existing data, fetch it
    fetch(`/api/alerts/${alertId}?index=${alertIndex}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(alert => {
            renderAlertDetails(alert, detailsBody);
            if (detailsLoader) {
                detailsLoader.style.display = 'none';
            }
        })
        .catch(error => {
            console.error('Error loading alert details:', error);
            if (detailsBody) {
                detailsBody.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        Error loading alert details: ${error.message}
                    </div>
                `;
            }
            if (detailsLoader) {
                detailsLoader.style.display = 'none';
            }
        });
}

/**
 * Render alert details in the modal
 */
function renderAlertDetails(alert, container) {
    if (!container) return;

    // Get the source data
    const source = alert._source || alert.source;
    if (!source) {
        container.innerHTML = '<div class="alert alert-warning">No alert details available</div>';
        return;
    }

    // Create sections for different parts of the alert
    let html = `
        <div class="alert-detail-section">
            <h5>Basic Information</h5>
            <table class="table table-sm table-bordered">
                <tr>
                    <th>Timestamp</th>
                    <td>${formatDate(source['@timestamp'])}</td>
                </tr>
                <tr>
                    <th>Alert ID</th>
                    <td>${alert._id || alert.id || 'N/A'}</td>
                </tr>
                <tr>
                    <th>Index</th>
                    <td>${alert._index || alert.index || 'N/A'}</td>
                </tr>
            </table>
        </div>
    `;

    // Rule information
    if (source.rule) {
        const rule = source.rule;

        // Determine severity class
        let severityClass = 'severity-low';
        let severityText = 'Low';
        const level = rule.level || 0;

        if (level >= 15) {
            severityClass = 'severity-critical';
            severityText = 'Critical';
        } else if (level >= 12) {
            severityClass = 'severity-high';
            severityText = 'High';
        } else if (level >= 7) {
            severityClass = 'severity-medium';
            severityText = 'Medium';
        }

        html += `
            <div class="alert-detail-section">
                <h5>Rule Information</h5>
                <table class="table table-sm table-bordered">
                    <tr>
                        <th>Rule ID</th>
                        <td>${rule.id || 'N/A'}</td>
                    </tr>
                    <tr>
                        <th>Description</th>
                        <td>${rule.description || 'N/A'}</td>
                    </tr>
                    <tr>
                        <th>Level</th>
                        <td class="${severityClass}">${severityText} (${level})</td>
                    </tr>
                    <tr>
                        <th>Groups</th>
                        <td>${Array.isArray(rule.groups) ? rule.groups.join(', ') : 'N/A'}</td>
                    </tr>
                </table>
            </div>
        `;
    }

    // Agent information
    if (source.agent) {
        const agent = source.agent;

        html += `
            <div class="alert-detail-section">
                <h5>Agent Information</h5>
                <table class="table table-sm table-bordered">
                    <tr>
                        <th>Agent ID</th>
                        <td>${agent.id || 'N/A'}</td>
                    </tr>
                    <tr>
                        <th>Name</th>
                        <td>${agent.name || 'N/A'}</td>
                    </tr>
                    <tr>
                        <th>IP</th>
                        <td>${agent.ip || 'N/A'}</td>
                    </tr>
                </table>
            </div>
        `;
    }

    // Raw data (collapsed by default)
    html += `
        <div class="alert-detail-section">
            <h5>Raw Data</h5>
            <div class="accordion" id="rawDataAccordion">
                <div class="accordion-item">
                    <h2 class="accordion-header" id="rawDataHeading">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" 
                                data-bs-target="#rawDataCollapse" aria-expanded="false" aria-controls="rawDataCollapse">
                            View Raw JSON
                        </button>
                    </h2>
                    <div id="rawDataCollapse" class="accordion-collapse collapse" aria-labelledby="rawDataHeading" data-bs-parent="#rawDataAccordion">
                        <div class="accordion-body">
                            <pre class="bg-dark text-light p-3 rounded">${JSON.stringify(source, null, 2)}</pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Set the HTML content
    container.innerHTML = html;
}

/**
 * Format date to a nice readable format
 */
function formatDate(dateStr) {
    if (!dateStr) return 'N/A';

    try {
        const date = new Date(dateStr);
        return date.toLocaleString();
    } catch (e) {
        console.error('Error formatting date:', e);
        return dateStr;
    }
}

/**
 * Load alert configurations
 */
function loadAlertConfigs() {
    const alertsTable = document.getElementById('alert-configs-table-body');
    if (!alertsTable) return;

    // Show loading indicator
    alertsTable.innerHTML = `
        <tr>
            <td colspan="5" class="text-center">
                <div class="d-flex justify-content-center">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                </div>
            </td>
        </tr>
    `;

    fetch('/api/alert_configs')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(alerts => {
            displayAlertConfigs(alerts, alertsTable);
        })
        .catch(error => {
            console.error('Error loading alert configs:', error);
            alertsTable.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center">
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            Error loading alert configurations: ${error.message}
                        </div>
                    </td>
                </tr>
            `;
        });
}

/**
 * Display alert configurations in the table
 */
function displayAlertConfigs(alerts, container) {
    // Clear container
    container.innerHTML = '';

    if (!alerts || alerts.length === 0) {
        container.innerHTML = `
            <tr>
                <td colspan="5" class="text-center">
                    <div class="alert alert-info">
                        No alert configurations found. Create one to get started.
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    // Loop through alert configs and create table rows
    alerts.forEach(alert => {
        const row = document.createElement('tr');

        // Format alert levels
        const levels = alert.alert_levels.map(level => 
            `<span class="badge bg-severity-${level}">${level.charAt(0).toUpperCase() + level.slice(1)}</span>`
        ).join(' ');

        // Format created date
        const createdDate = new Date(alert.created_at).toLocaleString();

        row.innerHTML = `
            <td>${alert.name}</td>
            <td>${levels}</td>
            <td>${alert.email_recipient}</td>
            <td>${alert.enabled ? '<span class="badge bg-success">Enabled</span>' : '<span class="badge bg-danger">Disabled</span>'}</td>
            <td>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-info btn-test" data-id="${alert.id}" title="Test Alert">
                        <i class="fas fa-paper-plane"></i>
                    </button>
                    <button class="btn btn-warning btn-edit" data-id="${alert.id}" title="Edit Alert">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-danger btn-delete" data-id="${alert.id}" title="Delete Alert">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;

        container.appendChild(row);
    });

    // Add event listeners to buttons
    addAlertButtonListeners();
}

/**
 * Add event listeners to alert action buttons
 */
function addAlertButtonListeners() {
    // Test alert buttons
    document.querySelectorAll('.btn-test').forEach(button => {
        button.addEventListener('click', function() {
            const alertId = this.getAttribute('data-id');
            testAlert(alertId);
        });
    });

    // Edit alert buttons
    document.querySelectorAll('.btn-edit').forEach(button => {
        button.addEventListener('click', function() {
            const alertId = this.getAttribute('data-id');
            editAlert(alertId);
        });
    });

    // Delete alert buttons
    document.querySelectorAll('.btn-delete').forEach(button => {
        button.addEventListener('click', function() {
            const alertId = this.getAttribute('data-id');
            deleteAlert(alertId);
        });
    });
}

/**
 * Test an alert configuration
 */
function testAlert(alertId) {
            if (confirm('Send a test alert email for this configuration?')) {
                fetch(`/api/alert_configs/${alertId}/test`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        showMessage(data.error, 'error');
                    } else {
                        showMessage(data.message, 'success');
                    }
                })
                .catch(error => {
                    console.error('Error testing alert:', error);
                    showMessage('Failed to test alert', 'error');
                });
            }
        }

        function debugAlert(alertId) {
            fetch(`/api/alert_configs/${alertId}/debug`)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        showMessage(data.error, 'error');
                        return;
                    }

                    // Create debug info modal
                    const debugInfo = `
                        <div class="modal fade" id="debugModal" tabindex="-1">
                            <div class="modal-dialog modal-lg">
                                <div class="modal-content">
                                    <div class="modal-header">
                                        <h5 class="modal-title">Alert Configuration Debug Info</h5>
                                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                    </div>
                                    <div class="modal-body">
                                        <h6>Configuration</h6>
                                        <pre>${JSON.stringify(data.alert_config, null, 2)}</pre>

                                        <h6>Current Time</h6>
                                        <pre>${JSON.stringify(data.current_time, null, 2)}</pre>

                                        <h6>Recent Alerts (Last Hour)</h6>
                                        <pre>${JSON.stringify(data.recent_alerts, null, 2)}</pre>

                                        <h6>Recent Sent Alerts (Last 24h)</h6>
                                        <pre>${JSON.stringify(data.sent_alerts, null, 2)}</pre>

                                        <h6>SMTP Configuration</h6>
                                        <pre>${JSON.stringify(data.smtp_config, null, 2)}</pre>
                                    </div>
                                    <div class="modal-footer">
                                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;

                    // Remove existing modal if any
                    const existingModal = document.getElementById('debugModal');
                    if (existingModal) {
                        existingModal.remove();
                    }

                    // Add new modal
                    document.body.insertAdjacentHTML('beforeend', debugInfo);

                    // Show modal
                    const modal = new bootstrap.Modal(document.getElementById('debugModal'));
                    modal.show();
                })
                .catch(error => {
                    console.error('Error debugging alert:', error);
                    showMessage('Failed to debug alert', 'error');
                });
        }

/**
 * Edit an existing alert configuration
 */
function editAlert(alertId) {
    // Show loading modal
    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();

    // Fetch the alert configuration
    fetch('/api/alert_configs')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(alerts => {
            const alert = alerts.find(a => a.id.toString() === alertId.toString());
            if (!alert) {
                throw new Error('Alert configuration not found');
            }

            loadingModal.hide();

            // Populate the form
            const form = document.getElementById('edit-alert-form');
            if (!form) return;

            document.getElementById('edit-alert-id').value = alert.id;
            document.getElementById('edit-alert-name').value = alert.name;

            // Set alert level checkboxes
            const levelCheckboxes = document.querySelectorAll('input[name="edit-alert-level"]');
            levelCheckboxes.forEach(checkbox => {
                checkbox.checked = alert.alert_levels.includes(checkbox.value);
            });

            // Set include fields checkboxes
            const includeFieldsCheckboxes = document.querySelectorAll('input[name="edit-include-field"]');
            if (includeFieldsCheckboxes && alert.include_fields) {
                includeFieldsCheckboxes.forEach(checkbox => {
                    checkbox.checked = alert.include_fields.includes(checkbox.value);
                });
            } else if (includeFieldsCheckboxes) {
                // Default values if no include_fields is set
                const defaultFields = ["@timestamp", "agent.ip", "agent.labels.location.set", "agent.name", "rule.description", "rule.id"];
                includeFieldsCheckboxes.forEach(checkbox => {
                    checkbox.checked = defaultFields.includes(checkbox.value);
                });
            }

            // Set email recipient
            document.getElementById('edit-email-recipient').value = alert.email_recipient;

            // Set notify time
            document.getElementById('edit-notify-time').value = alert.notify_time || '';

            // Set enabled status
            document.getElementById('edit-alert-enabled').checked = alert.enabled;

            // Show the modal
            const editModal = new bootstrap.Modal(document.getElementById('edit-alert-modal'));
            editModal.show();
        })
        .catch(error => {
            console.error('Error loading alert for editing:', error);
            loadingModal.hide();

            // Show error message
            const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = `Error loading alert: ${error.message}`;
            }
            errorModal.show();
        });

    // Set up form submit handler if not already set
    const editForm = document.getElementById('edit-alert-form');
    if (editForm && !editForm.hasAttribute('data-handler-attached')) {
        editForm.setAttribute('data-handler-attached', 'true');
        editForm.addEventListener('submit', handleEditAlert);
    }
}

/**
 * Delete an alert configuration
 */
function deleteAlert(alertId) {
    // Show confirmation dialog
    if (!confirm('Are you sure you want to delete this alert configuration?')) {
        return;
    }

    fetch(`/api/alert_configs/${alertId}`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(response => {
            if (!response.ok) {
                // Try to parse as JSON, fallback to text
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    return response.json().then(data => {
                        throw new Error(data.error || `HTTP error! Status: ${response.status}`);
                    });
                } else {
                    return response.text().then(text => {
                        throw new Error(`Server error: ${response.status} - ${text.substring(0, 100)}`);
                    });
                }
            }
            return response.json();
        })
        .then(data => {
            // Reload alert configs
            loadAlertConfigs();

            // Show success message
            showSuccessMessage(data.message || 'Alert configuration deleted successfully!');
        })
        .catch(error => {
            console.error('Error deleting alert:', error);
            showErrorMessage(`Error deleting alert: ${error.message}`);
        });
}

/**
 * Handle create alert form submission
 */
function handleCreateAlert(event) {
    event.preventDefault();

    // Get form values
    const alertName = document.getElementById('alert-name').value;
    const emailRecipient = document.getElementById('email-recipient').value;
    const notifyTime = document.getElementById('notify-time').value;
    const enabled = document.getElementById('alert-enabled').checked;

    // Get selected alert levels
    const alertLevels = [];
    document.querySelectorAll('input[name="alert-level"]:checked').forEach(checkbox => {
        alertLevels.push(checkbox.value);
    });

    // Get selected include fields
    const includeFields = [];
    document.querySelectorAll('input[name="include-field"]:checked').forEach(checkbox => {
        includeFields.push(checkbox.value);
    });

    // Validate
    if (!alertName) {
        alert('Please enter an alert name');
        return;
    }

    if (alertLevels.length === 0) {
        alert('Please select at least one alert level');
        return;
    }

    if (!emailRecipient) {
        alert('Please enter an email recipient');
        return;
    }

    if (includeFields.length === 0) {
        alert('Please select at least one field to include in alerts');
        return;
    }

    // Create alert data
    const alertData = {
        name: alertName,
        alert_levels: alertLevels,
        email_recipient: emailRecipient,
        notify_time: notifyTime,
        enabled: enabled,
        include_fields: includeFields
    };

    // Show loading modal
    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();

    // Submit to API
    fetch('/api/alert_configs', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(alertData)
    })
        .then(response => {
            if (!response.ok) {
                // Try to parse as JSON, fallback to text
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    return response.json().then(data => {
                        throw new Error(data.error || `HTTP error! Status: ${response.status}`);
                    });
                } else {
                    return response.text().then(text => {
                        throw new Error(`Server error: ${response.status} - ${text.substring(0, 100)}`);
                    });
                }
            }
            return response.json();
        })
        .then(data => {
            loadingModal.hide();

            // Reset form
            document.getElementById('create-alert-form').reset();

            // Hide the modal
            const createModal = bootstrap.Modal.getInstance(document.getElementById('create-alert-modal'));
            if (createModal) {
                createModal.hide();
            }

            // Reload alert configs
            loadAlertConfigs();

            // Show success message
            showSuccessMessage(data.message || 'Alert configuration created successfully!');
        })
        .catch(error => {
            console.error('Error creating alert:', error);
            loadingModal.hide();
            showErrorMessage(`Error creating alert: ${error.message}`);
        });
}

/**
 * Display pagination controls
 */
function displayPagination(totalAlerts) {
    const paginationContainer = document.getElementById('alerts-pagination');
    if (!paginationContainer) return;

    if (totalPages <= 1) {
        paginationContainer.innerHTML = '';
        return;
    }

    let paginationHTML = '<nav aria-label="Alerts pagination"><ul class="pagination justify-content-center">';

    // Previous button
    if (currentPage > 1) {
        paginationHTML += `
            <li class="page-item">
                <a class="page-link" href="#" onclick="loadSecurityAlerts(${currentPage - 1}); return false;">Previous</a>
            </li>
        `;
    } else {
        paginationHTML += '<li class="page-item disabled"><span class="page-link">Previous</span></li>';
    }

    // Page numbers
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);

    if (startPage > 1) {
        paginationHTML += '<li class="page-item"><a class="page-link" href="#" onclick="loadSecurityAlerts(1); return false;">1</a></li>';
        if (startPage > 2) {
            paginationHTML += '<li class="page-item disabled"><span class="page-link">...</span></li>';
        }
    }

    for (let page = startPage; page <= endPage; page++) {
        if (page === currentPage) {
            paginationHTML += `<li class="page-item active"><span class="page-link">${page}</span></li>`;
        } else {
            paginationHTML += `<li class="page-item"><a class="page-link" href="#" onclick="loadSecurityAlerts(${page}); return false;">${page}</a></li>`;
        }
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            paginationHTML += '<li class="page-item disabled"><span class="page-link">...</span></li>';
        }
        paginationHTML += `<li class="page-item"><a class="page-link" href="#" onclick="loadSecurityAlerts(${totalPages}); return false;">${totalPages}</a></li>`;
    }

    // Next button
    if (currentPage < totalPages) {
        paginationHTML += `
            <li class="page-item">
                <a class="page-link" href="#" onclick="loadSecurityAlerts(${currentPage + 1}); return false;">Next</a>
            </li>
        `;
    } else {
        paginationHTML += '<li class="page-item disabled"><span class="page-link">Next</span></li>';
    }

    paginationHTML += '</ul></nav>';

    // Add showing results info
    const startRecord = (currentPage - 1) * alertsPerPage + 1;
    const endRecord = Math.min(currentPage * alertsPerPage, totalAlerts);
    paginationHTML += `<div class="text-center mt-2"><small class="text-muted">Showing ${startRecord}-${endRecord} of ${totalAlerts} alerts</small></div>`;

    paginationContainer.innerHTML = paginationHTML;
}

/**
 * Handle edit alert form submission
 */
function handleEditAlert(event) {
    event.preventDefault();

    // Get form values
    const alertId = document.getElementById('edit-alert-id').value;
    const alertName = document.getElementById('edit-alert-name').value;
    const emailRecipient = document.getElementById('edit-email-recipient').value;
    const notifyTime = document.getElementById('edit-notify-time').value;
    const enabled = document.getElementById('edit-alert-enabled').checked;

    // Get selected alert levels
    const alertLevels = [];
    document.querySelectorAll('input[name="edit-alert-level"]:checked').forEach(checkbox => {
        alertLevels.push(checkbox.value);
    });

    // Get selected include fields
    const includeFields = [];
    document.querySelectorAll('input[name="edit-include-field"]:checked').forEach(checkbox => {
        includeFields.push(checkbox.value);
    });

    // Validate
    if (!alertName) {
        alert('Please enter an alert name');
        return;
    }

    if (alertLevels.length === 0) {
        alert('Please select at least one alert level');
        return;
    }

    if (!emailRecipient) {
        alert('Please enter an email recipient');
        return;
    }

    if (includeFields.length === 0) {
        alert('Please select at least one field to include in alerts');
        return;
    }

    // Create alert data
    const alertData = {
        name: alertName,
        alert_levels: alertLevels,
        email_recipient: emailRecipient,
        notify_time: notifyTime,
        enabled: enabled,
        include_fields: includeFields
    };

    // Show loading modal
    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();

    // Submit to API
    fetch(`/api/alert_configs/${alertId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(alertData)
    })
        .then(response => {
            if (!response.ok) {
                // Try to parse as JSON, fallback to text
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    return response.json().then(data => {
                        throw new Error(data.error || `HTTP error! Status: ${response.status}`);
                    });
                } else {
                    return response.text().then(text => {
                        throw new Error(`Server error: ${response.status} - ${text.substring(0, 100)}`);
                    });
                }
            }
            return response.json();
        })
        .then(data => {
            loadingModal.hide();

            // Hide the modal
            const editModal = bootstrap.Modal.getInstance(document.getElementById('edit-alert-modal'));
            if (editModal) {
                editModal.hide();
            }

            // Reload alert configs
            loadAlertConfigs();

            // Show success message
            showSuccessMessage(data.message || 'Alert configuration updated successfully!');
        })
        .catch(error => {
            console.error('Error updating alert:', error);
            loadingModal.hide();
            showErrorMessage(`Error updating alert: ${error.message}`);
        });
}

// Auto-refresh alerts every 30 seconds
        setInterval(function() {
            refreshAlertsTable();
        }, 30000);

        // Manual alert check button
        const manualCheckBtn = document.getElementById('manual-alert-check-btn');
        if (manualCheckBtn) {
            manualCheckBtn.addEventListener('click', function() {
                this.disabled = true;
                this.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Checking...';

                fetch('/api/alerts/manual_check', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.message) {
                        showSuccessMessage('Alert check completed successfully');
                    } else {
                        showErrorMessage(data.error || 'Failed to check alerts');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showErrorMessage('Error checking alerts: ' + error.message);
                })
                .finally(() => {
                    this.disabled = false;
                    this.innerHTML = '<i class="fas fa-play me-2"></i>Check Alerts Now';
                });
            });
        }

/**
 * Show a success message using the modal
 */
function showSuccessMessage(message) {
    const successModal = new bootstrap.Modal(document.getElementById('success-modal'));
    const successMessage = document.getElementById('success-message');
    if (successMessage) {
        successMessage.textContent = message || 'Success!';
    }
    successModal.show();
}

/**
 * Show an error message using the modal
 */
function showErrorMessage(message) {
    const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
    const errorMessage = document.getElementById('error-message');
    if (errorMessage) {
        errorMessage.textContent = message || 'Error!';
    }
    errorModal.show();
}

/**
 * Refresh alerts table
 */
function refreshAlertsTable() {
    loadSecurityAlerts();
}