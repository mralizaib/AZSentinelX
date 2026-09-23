/**
 * Alerts JavaScript - REBIZ Sentinel X
 * Handles security alerts fetching, filtering, and alert configuration
 */

/**
 * Fetch wrapper that handles 401 (session expired) gracefully.
 * Returns the same Promise chain as fetch() but intercepts 401 responses
 * before they can cause JSON-parse errors.
 */
function apiFetch(url, options) {
    return fetch(url, options).then(response => {
        if (response.status === 401) {
            // Session expired — redirect to login
            window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname);
            // Return a never-resolving promise so downstream .then() handlers don't run
            return new Promise(() => {});
        }
        return response;
    });
}

function compactAlertKey(value) {
    return String(value ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function alertField(object, ...keys) {
    if (!object || typeof object !== 'object') return '';
    for (const key of keys) {
        if (object[key] !== undefined && object[key] !== null && object[key] !== '') {
            return object[key];
        }
    }
    const aliases = new Map(
        Object.keys(object).map(key => [compactAlertKey(key), object[key]])
    );
    for (const key of keys) {
        const value = aliases.get(compactAlertKey(key));
        if (value !== undefined && value !== null && value !== '') return value;
    }
    return '';
}

function alertPayload(source) {
    if (!source || typeof source !== 'object') return {};
    if (source.data?.win && typeof source.data.win === 'object') return source;

    const candidates = [source.full_log, source.message, source.event?.original];
    for (const candidate of candidates) {
        if (typeof candidate !== 'string' || !candidate.trim()) continue;
        try {
            const parsed = JSON.parse(candidate);
            if (parsed && typeof parsed === 'object') return parsed;
        } catch (e) {
            // Some Wazuh records contain plain text rather than JSON.
        }
    }
    return source;
}

function buildAlertSummary(alert, source, description) {
    const payload = alertPayload(source);
    const data = payload?.data && typeof payload.data === 'object' ? payload.data : {};
    const win = (data.win && typeof data.win === 'object')
        ? data.win
        : (payload.win && typeof payload.win === 'object' ? payload.win : {});
    const eventData = win.eventdata && typeof win.eventdata === 'object' ? win.eventdata : {};
    const system = win.system && typeof win.system === 'object' ? win.system : {};
    const eventId = alertField(system, 'eventID', 'event id');
    const logonType = String(alertField(eventData, 'logonType', 'logon type')).trim();
    const sourceIp = alertField(eventData, 'ipAddress', 'ip address', 'sourceIp', 'source ip');
    const account = alertField(
        eventData,
        'targetUserName', 'target user name',
        'subjectUserName', 'subject user name',
        'accountName', 'account name'
    );
    const workstation = alertField(eventData, 'workstationName', 'workstation name');
    const action = alertField(eventData, 'actionName', 'action name', 'executionName', 'execution name');
    const context = [];

    if (eventId) context.push(`Event ID ${eventId}`);
    if (logonType === '10' || /remote.?interactive|rdp/i.test(logonType)) {
        context.push('Remote Interactive (RDP)');
    }
    if (account) context.push(`Account: ${account}`);
    if (sourceIp) context.push(`Source IP: ${sourceIp}`);
    if (workstation) context.push(`Workstation: ${workstation}`);
    if (action) context.push(`Action: ${action}`);

    const cleanDescription = String(description || '').trim();
    const looksLikeJson = cleanDescription.startsWith('{') || cleanDescription.startsWith('[');
    const base = cleanDescription && cleanDescription !== 'N/A' && !looksLikeJson
        ? cleanDescription
        : (eventId ? `Windows Security event ${eventId}` : 'Windows security event');

    return context.length ? `${base} — ${context.join(' · ')}` : base;
}

document.addEventListener('DOMContentLoaded', function() {
    // Wire this before any optional storage/API work so the calendar UI remains
    // usable even if another page enhancement fails.
    setupCalendarFilter();

    // Load alert configurations
    loadAlertConfigs();

    // Restore saved filter state from sessionStorage (set when navigating to alert details)
    const savedState = sessionStorage.getItem('alerts_filter_state');
    let restoredPage = 1;
    let stateRestored = false;

    if (savedState) {
        try {
            const state = JSON.parse(savedState);
            sessionStorage.removeItem('alerts_filter_state');

            // Restore severity checkboxes
            if (state.severities && state.severities.length > 0) {
                document.querySelectorAll('input[name="severity-filter"]').forEach(cb => {
                    cb.checked = state.severities.includes(cb.value);
                });
            }

            // Restore time range
            const timeRangeEl = document.getElementById('time-range-filter');
            if (timeRangeEl && state.timeRange) timeRangeEl.value = state.timeRange;
            const calendarStart = document.getElementById('calendar-start-date');
            const calendarEnd = document.getElementById('calendar-end-date');
            if (calendarStart && state.startDate) calendarStart.value = state.startDate;
            if (calendarEnd && state.endDate) calendarEnd.value = state.endDate;
            const decoderEl = document.getElementById('syslog-decoder-filter');
            // Older versions automatically saved "syscollector" even when
            // the user never selected a decoder. Do not resurrect that stale
            // implicit filter after the all-decoder Syslog behavior is enabled.
            if (decoderEl && state.decoderQuery &&
                state.decoderQuery.trim().toLowerCase() !== 'syscollector') {
                decoderEl.value = state.decoderQuery;
            }

            // Restore search query
            const searchEl = document.getElementById('search-filter');
            if (searchEl && state.searchQuery) searchEl.value = state.searchQuery;

            // Restore rule filter
            const ruleEl = document.getElementById('rule-filter');
            if (ruleEl && state.ruleId) ruleEl.value = state.ruleId;

            restoredPage = state.page || 1;
            stateRestored = true;
        } catch(e) {
            console.warn('Failed to restore filter state:', e);
        }
    }

    if (!stateRestored) {
        // Check for severity filter in URL
        const urlParams = new URLSearchParams(window.location.search);
        const severityParam = urlParams.get('severity');
        const ruleIdParam = urlParams.get('rule_id');

        if (severityParam === 'all' || ruleIdParam) {
            // Show all severity levels (rule-based or explicit all filter)
            document.querySelectorAll('input[name="severity-filter"]').forEach(cb => {
                cb.checked = true;
            });
        } else if (severityParam) {
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

        // If rule_id is in URL, make sure the hidden rule-filter input is set
        // (already set server-side in the template, but also handle client-side for robustness)
        if (ruleIdParam) {
            const ruleEl = document.getElementById('rule-filter');
            if (ruleEl && !ruleEl.value) ruleEl.value = ruleIdParam;
        }
    }

    // Restore/default checkbox state before calculating the Syslog section
    // visibility, so navigation back to a Syslog search preserves the UI.
    setupSyslogFilter();

    // Load security alerts with restored or default filters
    loadSecurityAlerts(restoredPage);

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

    // FIM toggle — Create modal
    document.querySelectorAll('input[name="alert-type"]').forEach(radio => {
        radio.addEventListener('change', function() {
            const isFim = this.value === 'fim';
            const stdSection = document.getElementById('create-standard-section');
            const fimSection = document.getElementById('create-fim-section');
            const fieldsSection = document.getElementById('create-include-fields-section');
            if (stdSection)    stdSection.style.display  = isFim ? 'none' : '';
            if (fimSection)    fimSection.style.display   = isFim ? '' : 'none';
            if (fieldsSection) fieldsSection.style.display = isFim ? 'none' : '';
        });
    });

    // FIM toggle — Edit modal
    document.querySelectorAll('input[name="edit-alert-type"]').forEach(radio => {
        radio.addEventListener('change', function() {
            const isFim = this.value === 'fim';
            const stdSection = document.getElementById('edit-standard-section');
            const fimSection = document.getElementById('edit-fim-section');
            const fieldsSection = document.getElementById('edit-include-fields-section');
            if (stdSection)    stdSection.style.display  = isFim ? 'none' : '';
            if (fimSection)    fimSection.style.display   = isFim ? '' : 'none';
            if (fieldsSection) fieldsSection.style.display = isFim ? 'none' : '';
        });
    });

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

    // Auto-refresh alerts every 30 seconds — preserves current page, skips if user has an active search
    setInterval(function() {
        const searchQuery = document.getElementById('search-filter')?.value?.trim();
        if (!searchQuery) {
            loadSecurityAlerts(currentPage);
        }
    }, 30000);

    // Manual alert check button
    const manualCheckBtn = document.getElementById('manual-alert-check-btn');
    if (manualCheckBtn) {
        manualCheckBtn.addEventListener('click', function() {
            this.disabled = true;
            this.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Checking...';

            fetch('/api/alerts/manual_check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
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
            <td colspan="9" class="text-center">
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
    let calendarRange = null;
    if (timeRange === 'calendar') {
        calendarRange = readCalendarRange('applying filters');
        if (calendarRange.error) {
            displayCalendarValidation(calendarRange.error);
            alertsContainer.innerHTML = `
                <tr>
                    <td colspan="9" class="text-center text-muted py-4">
                        ${escapeHtml(calendarRange.error)}
                    </td>
                </tr>
            `;
            return;
        }
        params.append('start_date', calendarRange.startDate);
        params.append('end_date', calendarRange.endDate);
    }

    // Add pagination parameters
    params.append('limit', alertsPerPage);
    params.append('offset', (currentPage - 1) * alertsPerPage);

    // Additional filters
    const searchQuery = document.getElementById('search-filter')?.value;
    if (searchQuery && searchQuery.trim()) {
        params.append('search_query', searchQuery.trim());
    }

    const decoderQuery = document.getElementById('syslog-decoder-filter')?.value;
    if (decoderQuery && decoderQuery.trim()) {
        params.append('decoder', decoderQuery.trim());
    }

    const ruleId = document.getElementById('rule-filter')?.value;
    if (ruleId) {
        params.append('rule_id', ruleId);
    }

    // Fetch alerts
    apiFetch(`/api/alerts?${params.toString()}`)
        .then(response => {
            return response.json().catch(() => ({})).then(data => {
                if (!response.ok) {
                    throw new Error(data.error || `HTTP error! Status: ${response.status}`);
                }
                return data;
            });
        })
        .then(data => {
            displayAlerts(data, alertsContainer);
            const rangeStatus = document.getElementById('alert-range-status');
            if (rangeStatus) {
                rangeStatus.textContent = `${data.server_name || 'Selected server'} · ${data.date_range?.label || 'selected period'} · ${data.server_timezone_label || data.server_timezone || 'UTC'}`;
            }
            const calendarTimezoneLabel = document.getElementById('calendar-timezone-label');
            if (calendarTimezoneLabel) {
                calendarTimezoneLabel.textContent = `(${data.server_timezone_label || data.server_timezone || 'UTC'})`;
            }

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
                    <td colspan="9" class="text-center">
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

    const fmtLower = format.toLowerCase();
    const exportBtn = document.querySelector(`#export-${fmtLower}`);
    let originalText = '';

    if (exportBtn) {
        originalText = exportBtn.innerHTML;
        exportBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Exporting...';
        exportBtn.disabled = true;
    }

    function resetBtn() {
        if (exportBtn) {
            exportBtn.innerHTML = originalText;
            exportBtn.disabled = false;
        }
    }

    // Get current filter values
    const severityLevels = [];
    document.querySelectorAll('input[name="severity-filter"]:checked').forEach(cb => severityLevels.push(cb.value));
    const timeRange = document.getElementById('time-range-filter')?.value || '24h';

    const params = new URLSearchParams();
    severityLevels.forEach(level => params.append('severity_levels[]', level));
    params.append('time_range', timeRange);
    params.append('format', fmtLower);

    if (timeRange === 'calendar') {
        const calendarRange = readCalendarRange('exporting');
        if (calendarRange.error) {
            resetBtn();
            displayCalendarValidation(calendarRange.error);
            return;
        }
        params.append('start_date', calendarRange.startDate);
        params.append('end_date', calendarRange.endDate);
    }

    const searchQuery = document.getElementById('search-filter')?.value;
    if (searchQuery) params.append('search_query', searchQuery);

    const ruleId = document.getElementById('rule-filter')?.value;
    if (ruleId) params.append('rule_id', ruleId);

    const exportUrl = `/api/alerts/export?${params.toString()}`;

    // Use fetch so the download doesn't cause the tab to navigate/spin
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 120000); // 2-min timeout

    fetch(exportUrl, { signal: controller.signal })
        .then(response => {
            clearTimeout(timeoutId);
            if (!response.ok) {
                return response.json().then(data => { throw new Error(data.error || `Server error (${response.status})`); });
            }
            return response.blob().then(blob => {
                // Determine filename extension
                const ext = fmtLower === 'xlsx' ? 'xlsx' : fmtLower === 'pdf' ? 'pdf' : 'csv';
                const filename = `alerts_export_${new Date().toISOString().slice(0,19).replace(/[T:]/g, '-')}.${ext}`;
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                setTimeout(() => { window.URL.revokeObjectURL(url); document.body.removeChild(a); }, 500);
                resetBtn();
            });
        })
        .catch(error => {
            clearTimeout(timeoutId);
            resetBtn();
            const msg = error.name === 'AbortError'
                ? 'Export timed out. Try a shorter time range or fewer severity levels.'
                : `Export failed: ${error.message}`;
            alert(msg);
        });
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
function readableFieldLabel(key) {
    return String(key || '')
        .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
        .replace(/[._-]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .replace(/\b\w/g, character => character.toUpperCase());
}

function readableFieldValue(value) {
    if (value === null || value === undefined || value === '') return 'N/A';
    if (Array.isArray(value)) return value.map(item => readableFieldValue(item)).join(', ');
    if (typeof value === 'object') return JSON.stringify(value, null, 2);
    return String(value);
}

function flattenReadableFields(value, prefix = '', depth = 0) {
    if (value === null || value === undefined) return [];
    if (Array.isArray(value) || typeof value !== 'object' || depth >= 3) {
        return prefix ? [{ key: prefix, value }] : [];
    }

    const fields = [];
    Object.entries(value).forEach(([key, child]) => {
        const fieldKey = prefix ? `${prefix}.${key}` : key;
        if (child && typeof child === 'object' && !Array.isArray(child) && depth < 3) {
            fields.push(...flattenReadableFields(child, fieldKey, depth + 1));
        } else {
            fields.push({ key: fieldKey, value: child });
        }
    });
    return fields;
}

function buildReadableSyslogHtml(alert, source) {
    const payload = alert.event_data && typeof alert.event_data === 'object'
        ? alert.event_data
        : (source.data && typeof source.data === 'object' ? source.data : {});
    const originalMessage = alert.syslog_message && alert.syslog_message !== 'N/A'
        ? alert.syslog_message
        : (source.full_log || source.message || source.syslog?.message || source.event?.original || '');
    const operation = alert.event_operation && alert.event_operation !== 'N/A'
        ? alert.event_operation
        : (source.operation || source.event?.action || '');
    const eventType = alert.event_type_name && alert.event_type_name !== 'N/A'
        ? alert.event_type_name
        : (source.type || source.event?.type || 'Decoded event');
    const eventName = alert.event_name && alert.event_name !== 'N/A'
        ? alert.event_name
        : (source.name || payload.name || '');
    const readableTitle = String(eventType).toLowerCase() === 'dbsync_processes'
        ? 'Process inventory change'
        : 'Decoded system event';
    const fields = flattenReadableFields(payload)
        .filter(field => !['operation', 'type'].includes(field.key.toLowerCase()));
    const additionalFields = flattenReadableFields(source)
        .filter(field => {
            const key = field.key.toLowerCase();
            return !key.startsWith('data.') &&
                !['@timestamp', 'full_log', 'message', 'syslog.message', 'event.original'].includes(key);
        });

    const fieldHtml = fields.length
        ? fields.map(field => `
            <div class="syslog-field">
                <span class="syslog-field-label">${escapeHtml(readableFieldLabel(field.key))}</span>
                <span class="syslog-field-value">${escapeHtml(readableFieldValue(field.value))}</span>
            </div>
        `).join('')
        : '<span class="text-muted">No decoded event fields available.</span>';
    const additionalFieldHtml = additionalFields.length
        ? additionalFields.map(field => `
            <div class="syslog-field">
                <span class="syslog-field-label">${escapeHtml(readableFieldLabel(field.key))}</span>
                <span class="syslog-field-value">${escapeHtml(readableFieldValue(field.value))}</span>
            </div>
        `).join('')
        : '';

    return `
        <details class="syslog-readable-log" open onclick="event.stopPropagation()">
            <summary>
                <span class="fw-semibold">${escapeHtml(readableTitle)}</span>
                ${operation ? `<span class="badge bg-warning text-dark ms-1">${escapeHtml(operation)}</span>` : ''}
                ${eventName ? `<span class="text-muted ms-1">${escapeHtml(eventName)}</span>` : ''}
            </summary>
            ${originalMessage ? `
                <div class="syslog-original-message mt-2">
                    <span class="syslog-field-label">Complete Syslog Message</span>
                    <pre class="syslog-original-message-value">${escapeHtml(readableFieldValue(originalMessage))}</pre>
                </div>
            ` : ''}
            <div class="syslog-field-grid mt-2">
                <div class="syslog-field">
                    <span class="syslog-field-label">Event Type</span>
                    <span class="syslog-field-value">${escapeHtml(eventType)}</span>
                </div>
                ${fieldHtml}
                ${additionalFieldHtml}
            </div>
        </details>
    `;
}

function displayAlerts(data, container) {
    // Clear container
    container.innerHTML = '';

    const results = data.results || [];

    if (results.length === 0) {
        const rangeLabel = data.date_range?.label || 'the selected period';
        const serverLabel = data.server_name || 'the selected server';
        container.innerHTML = `
            <tr>
                <td colspan="9" class="text-center">
                    <div class="alert alert-info">
                         No matching ${data.search_scope === 'syslog' ? 'Syslog records' : (data.search_scope === 'global' ? 'records' : 'alerts')} found for <strong>${escapeHtml(serverLabel)}</strong>
                        on <strong>${escapeHtml(rangeLabel)}</strong>.
                        Try a different search term, decoder, date range, or filter.
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    // Show notice when the severity filter was automatically relaxed
    if (data.severity_relaxed && data.original_severity_levels) {
        const noticeRow = document.createElement('tr');
        noticeRow.innerHTML = `
            <td colspan="9" class="py-2 px-3">
                <div class="alert alert-warning py-2 mb-0 small">
                    <i class="fas fa-search me-1"></i>
                    Search includes all alert categories, but keeps Syslog records in the separate Syslog filter.
                </div>
            </td>
        `;
        container.appendChild(noticeRow);
    }

    // Loop through alerts and create table rows
    results.forEach(alert => {
        const source = alert.source;
        if (!source) return;

        // Get values with fallbacks
        const isSyslog = alert.event_type === 'syslog';
        const timestamp = alert.timestamp || source['@timestamp'] || source.timestamp || 'N/A';
        const ruleId = alert.rule_id || source.rule?.id || 'N/A';
        const level = Number(alert.rule_level ?? source.rule?.level ?? 0) || 0;
        const description = alert.rule_description || source.rule?.description || 'N/A';
        const agentName = source.agent?.name || source.host?.name || 'N/A';
        const agentId = source.agent?.id || 'N/A';
        const serverName = alert.server_name || data.server_name || 'N/A';
        const serverTimezone = alert.server_timezone || data.server_timezone || 'UTC';
        const payload = alertPayload(source);
        const eventData = payload.data?.win?.eventdata ||
            payload.win?.eventdata ||
            {};
        const sourceDeviceIp = alert.source_device_ip ||
            source.agent?.ip ||
            alertField(eventData, 'ipAddress', 'ip address', 'sourceIp', 'source ip') ||
            'N/A';
        const destinationIp = alert.destination_ip || 'N/A';
        const deviceHostname = alert.device_hostname ||
            source.host?.name ||
            alertField(payload.data?.win?.system || payload.win?.system, 'computer', 'Computer') ||
            agentName;
        const decoderName = alert.decoder_name || source.decoder?.name || 'N/A';
        const message = alert.display_message ||
            (isSyslog
                ? (alert.syslog_message || description)
                : buildAlertSummary(alert, source, description));

        // Determine severity class
        let severityClass = 'severity-low';
        let severityText = 'Low';

        // Check if it's a Misc Event (based on description or Rule ID)
        const desc = String(description).toLowerCase();
        const ruleIdInt = parseInt(ruleId);
        const miscRuleIds = [750, 60642, 752, 550, 60106];
        const isMiscEvent = miscRuleIds.includes(ruleIdInt) || 
                            desc.includes('sonicwall warning') || 
                            desc.includes('sonicwall error') || 
                            desc.includes('integrity checksum changed') || 
                            desc.includes('registry value integrity checksum changed');

        if (isSyslog && level <= 0) {
            severityClass = 'text-warning';
            severityText = 'Syslog';
        } else if (isMiscEvent) {
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
            formattedDate = formatDate(timestamp, serverTimezone);
        } catch (e) {
            console.error('Error formatting date:', e);
        }

        // Create row
        const row = document.createElement('tr');
        row.className = 'clickable-row';
        row.style.cursor = 'pointer';
        row.setAttribute('data-id', alert.id);
        row.setAttribute('data-index', alert.index);
        const messageHtml = isSyslog
            ? buildReadableSyslogHtml(alert, source)
            : escapeHtml(message);

        row.innerHTML = `
            <td>${formattedDate}</td>
            <td><span class="badge bg-secondary">${escapeHtml(serverName)}</span></td>
            <td>${escapeHtml(sourceDeviceIp)}${isSyslog ? '' : ` <small class="text-muted">(${escapeHtml(agentId)})</small>`}</td>
            <td>${escapeHtml(destinationIp)}</td>
            <td>${escapeHtml(deviceHostname)}</td>
            <td><span class="badge bg-dark border border-warning text-warning">${escapeHtml(decoderName)}</span></td>
            <td>${escapeHtml(ruleId)}<br><span class="${severityClass}">${severityText}${level ? ` (${level})` : ''}</span></td>
            <td class="text-break" title="${isSyslog ? 'Readable decoded event details' : escapeHtml(message)}">${messageHtml}</td>
            <td>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-primary btn-view-details" data-id="${alert.id}" data-index="${alert.index}">
                        <i class="fas fa-search"></i> Details
                    </button>
                </div>
            </td>
        `;

        // Add click listener to the entire row
        row.addEventListener('click', function(e) {
            if (!e.target.closest('button')) {
                viewAlertDetails(alert.id, alert.index);
            }
        });

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
 * Save current filter state to sessionStorage before navigating away
 */
function saveFilterState() {
    const severities = [];
    document.querySelectorAll('input[name="severity-filter"]:checked').forEach(cb => severities.push(cb.value));
    const state = {
        severities,
        timeRange: document.getElementById('time-range-filter')?.value || '',
        startDate: document.getElementById('calendar-start-date')?.value || '',
        endDate: document.getElementById('calendar-end-date')?.value || '',
        searchQuery: document.getElementById('search-filter')?.value || '',
        decoderQuery: document.getElementById('syslog-decoder-filter')?.value || '',
        ruleId: document.getElementById('rule-filter')?.value || '',
        page: currentPage
    };
    sessionStorage.setItem('alerts_filter_state', JSON.stringify(state));
}

function viewAlertDetails(alertId, alertIndex) {
    saveFilterState();
    let url = `/alerts/view/${alertId}`;
    if (alertIndex) {
        url += `?index=${encodeURIComponent(alertIndex)}`;
    }
    window.location.href = url;
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
                    <td>${formatDate(source['@timestamp'], serverTimezoneForAlert(alert))}</td>
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
function serverTimezoneForAlert(alert) {
    return alert?.server_timezone || alert?.server_timezone_name || 'UTC';
}

function formatDate(dateStr, timeZone = 'UTC') {
    if (!dateStr) return 'N/A';

    try {
        const date = new Date(dateStr);
        if (Number.isNaN(date.getTime())) return dateStr;
        const parts = new Intl.DateTimeFormat('en-CA', {
            timeZone,
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hourCycle: 'h23',
            timeZoneName: 'short'
        }).formatToParts(date).reduce((result, part) => {
            result[part.type] = part.value;
            return result;
        }, {});
        return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second} ${parts.timeZoneName || timeZone}`;
    } catch (e) {
        console.error('Error formatting date:', e);
        return dateStr;
    }
}

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
    }[char]));
}

function displayCalendarValidation(message) {
    const status = document.getElementById('alert-range-status');
    if (status) status.textContent = message;
}

function readCalendarRange(action = 'applying filters') {
    const startDate = document.getElementById('calendar-start-date')?.value || '';
    const endDate = document.getElementById('calendar-end-date')?.value || startDate;
    if (!startDate) {
        return { error: `Choose a calendar date before ${action}.` };
    }
    if (endDate < startDate) {
        return { error: 'The end date cannot be earlier than the start date.' };
    }
    return { startDate, endDate };
}

function setupCalendarFilter() {
    const range = document.getElementById('time-range-filter');
    const fields = document.getElementById('calendar-range-fields');
    if (!range || !fields) return;

    const sync = () => {
        const isCalendar = range.value === 'calendar';
        fields.hidden = !isCalendar;
        fields.classList.toggle('d-none', !isCalendar);
        fields.setAttribute('aria-hidden', String(!isCalendar));
    };
    range.addEventListener('change', sync);
    sync();
}

function setupSyslogFilter() {
    const checkboxes = document.querySelectorAll('input[name="severity-filter"]');
    const fields = document.getElementById('syslog-filter-fields');
    if (!checkboxes.length || !fields) return;
    const syslogCheckbox = document.getElementById('filter-syslog');
    const decoderInput = document.getElementById('syslog-decoder-filter');

    const sync = () => {
        const syslogSelected = Boolean(syslogCheckbox?.checked);
        if (syslogSelected) {
            checkboxes.forEach(other => {
                if (other !== syslogCheckbox) other.checked = false;
            });
        }
        fields.hidden = !syslogSelected;
        fields.classList.toggle('d-none', !syslogSelected);
        fields.setAttribute('aria-hidden', String(!syslogSelected));
    };

    checkboxes.forEach(checkbox => checkbox.addEventListener('change', function() {
        // Syslog is a separate OpenSearch source. Prevent a mixed selection
        // from looking like one combined result set.
        if (this.value === 'syslog' && this.checked) {
            checkboxes.forEach(other => {
                if (other !== this) other.checked = false;
            });
        } else if (this.value !== 'syslog' && this.checked && syslogCheckbox) {
            syslogCheckbox.checked = false;
        }
        sync();
    }));
    sync();
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

    apiFetch('/api/alert_configs')
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

        const isFim = alert.alert_type === 'fim';
        const typeLabel = isFim
            ? '<span class="badge ms-1" style="background:#7c3aed;font-size:10px;"><i class="fas fa-file-shield me-1"></i>FIM</span>'
            : '';
        const levelsDisplay = isFim
            ? '<span class="text-muted small">— FIM events —</span>'
            : levels;

        row.innerHTML = `
            <td>${alert.name}${typeLabel}</td>
            <td>${levelsDisplay}</td>
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
                    <button class="btn btn-secondary btn-reset-dedup" data-id="${alert.id}" title="Clear sent-alert history so next check will resend">
                        <i class="fas fa-redo"></i>
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

    // Reset dedup buttons
    document.querySelectorAll('.btn-reset-dedup').forEach(button => {
        button.addEventListener('click', function() {
            const alertId = this.getAttribute('data-id');
            resetAlertDedup(alertId);
        });
    });
}

/**
 * Clear the sent-alert dedup history for an alert config so the next
 * check cycle will resend any events it finds.
 */
function resetAlertDedup(alertId) {
    if (!confirm('Clear sent-alert history for this config?\n\nThe next check cycle (within 2 min) will resend any events it finds.')) return;
    fetch(`/api/alert_configs/${alertId}/reset-dedup`, { method: 'DELETE' })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showToast(`✔ ${data.message}`, 'success');
            } else {
                showToast('Error: ' + (data.error || 'Unknown error'), 'danger');
            }
        })
        .catch(err => showToast('Request failed: ' + err, 'danger'));
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container') || (() => {
        const d = document.createElement('div');
        d.id = 'toast-container';
        d.style.cssText = 'position:fixed;top:20px;right:20px;z-index:9999;';
        document.body.appendChild(d);
        return d;
    })();
    const toast = document.createElement('div');
    toast.className = `alert alert-${type} alert-dismissible fade show shadow`;
    toast.style.cssText = 'min-width:280px;font-size:13px;';
    toast.innerHTML = `${message}<button type="button" class="btn-close" data-bs-dismiss="alert"></button>`;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
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
                showErrorMessage(data.error);
            } else {
                showSuccessMessage(data.message);
            }
        })
        .catch(error => {
            console.error('Error testing alert:', error);
            showErrorMessage('Failed to test alert: ' + error.message);
        });
    }
}

        function debugAlert(alertId) {
            fetch(`/api/alert_configs/${alertId}/debug`)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        showErrorMessage(data.error);
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
                    showErrorMessage('Failed to debug alert: ' + error.message);
                });
        }

/**
 * Edit an existing alert configuration
 */
function editAlert(alertId) {
    // Show loading modal (reuse existing instance if present)
    const loadingModalEl = document.getElementById('loading-modal');
    const loadingModal = bootstrap.Modal.getOrCreateInstance(loadingModalEl);
    loadingModal.show();

    // Fetch the alert configuration
    apiFetch('/api/alert_configs')
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

            // Wait for loading modal to fully hide before showing edit modal
            loadingModalEl.addEventListener('hidden.bs.modal', function onHidden() {
                loadingModalEl.removeEventListener('hidden.bs.modal', onHidden);

                // Populate the form
                const form = document.getElementById('edit-alert-form');
                if (!form) return;

                document.getElementById('edit-alert-id').value = alert.id;
                document.getElementById('edit-alert-name').value = alert.name;

                // ── Alert type: standard vs FIM ──────────────────────────
                const alertType = alert.alert_type || 'standard';
                const isFim = alertType === 'fim';

                const typeStdRadio = document.getElementById('edit-alert-type-standard');
                const typeFimRadio = document.getElementById('edit-alert-type-fim');
                if (typeStdRadio) typeStdRadio.checked = !isFim;
                if (typeFimRadio) typeFimRadio.checked = isFim;

                // Show/hide sections based on type
                const editStdSection   = document.getElementById('edit-standard-section');
                const editFimSection   = document.getElementById('edit-fim-section');
                const editFieldSection = document.getElementById('edit-include-fields-section');
                if (editStdSection)   editStdSection.style.display   = isFim ? 'none' : '';
                if (editFimSection)   editFimSection.style.display    = isFim ? '' : 'none';
                if (editFieldSection) editFieldSection.style.display  = isFim ? 'none' : '';

                // ── Standard alert level checkboxes ──────────────────────
                const levelCheckboxes = document.querySelectorAll('input[name="edit-alert-level"]');
                levelCheckboxes.forEach(checkbox => {
                    checkbox.checked = (alert.alert_levels || []).includes(checkbox.value);
                });

                // ── Include fields checkboxes ────────────────────────────
                const includeFieldsCheckboxes = document.querySelectorAll('input[name="edit-include-field"]');
                if (includeFieldsCheckboxes && alert.include_fields) {
                    includeFieldsCheckboxes.forEach(checkbox => {
                        checkbox.checked = alert.include_fields.includes(checkbox.value);
                    });
                } else if (includeFieldsCheckboxes) {
                    const defaultFields = ["@timestamp", "agent.ip", "agent.labels.location.set", "agent.name", "rule.description", "rule.id"];
                    includeFieldsCheckboxes.forEach(checkbox => {
                        checkbox.checked = defaultFields.includes(checkbox.value);
                    });
                }

                // ── FIM-specific fields ──────────────────────────────────
                const fimAgentNamesEl = document.getElementById('edit-fim-agent-names');
                const fimPathsEl      = document.getElementById('edit-fim-paths');
                const fimFileNamesEl  = document.getElementById('edit-fim-file-names');
                const fimFileExtsEl   = document.getElementById('edit-fim-file-extensions');

                if (fimAgentNamesEl) fimAgentNamesEl.value = (alert.fim_agent_names || []).join(', ');
                if (fimPathsEl)      fimPathsEl.value      = (alert.fim_paths || []).join(', ');
                if (fimFileNamesEl)  fimFileNamesEl.value  = (alert.fim_file_names || []).join(', ');
                if (fimFileExtsEl)   fimFileExtsEl.value   = (alert.fim_file_extensions || []).join(', ');

                // ── Standard fields ──────────────────────────────────────
                document.getElementById('edit-email-recipient').value = alert.email_recipient;
                document.getElementById('edit-notify-time').value = alert.notify_time || '';
                document.getElementById('edit-alert-enabled').checked = alert.enabled;

                // Show the edit modal
                const editModal = bootstrap.Modal.getOrCreateInstance(document.getElementById('edit-alert-modal'));
                editModal.show();
            });
            loadingModal.hide();
        })
        .catch(error => {
            console.error('Error loading alert for editing:', error);
            loadingModalEl.addEventListener('hidden.bs.modal', function onHidden() {
                loadingModalEl.removeEventListener('hidden.bs.modal', onHidden);
                showErrorMessage(`Error loading alert: ${error.message}`);
            });
            loadingModal.hide();
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

    // Determine alert type
    const alertTypeRadio = document.querySelector('input[name="alert-type"]:checked');
    const alertType = alertTypeRadio ? alertTypeRadio.value : 'standard';
    const isFimCreate = alertType === 'fim';

    // Get selected alert levels (only for standard)
    const alertLevels = [];
    document.querySelectorAll('input[name="alert-level"]:checked').forEach(checkbox => {
        alertLevels.push(checkbox.value);
    });

    // Get selected include fields (only for standard)
    const includeFields = [];
    document.querySelectorAll('input[name="include-field"]:checked').forEach(checkbox => {
        includeFields.push(checkbox.value);
    });

    // Validate
    if (!alertName) {
        alert('Please enter an alert name');
        return;
    }

    if (!isFimCreate && alertLevels.length === 0) {
        alert('Please select at least one alert level');
        return;
    }

    if (!emailRecipient) {
        alert('Please enter an email recipient');
        return;
    }

    if (!isFimCreate && includeFields.length === 0) {
        alert('Please select at least one field to include in alerts');
        return;
    }

    // FIM-specific validation
    if (isFimCreate) {
        const fimAgents = document.getElementById('fim-agent-names').value.trim();
        const fimPaths  = document.getElementById('fim-paths').value.trim();
        if (!fimAgents) { alert('FIM Alert requires at least one agent name.'); return; }
        if (!fimPaths)  { alert('FIM Alert requires at least one monitored path.'); return; }
    }

    // Build alert data payload
    const alertData = {
        name: alertName,
        alert_type: alertType,
        alert_levels: isFimCreate ? [] : alertLevels,
        email_recipient: emailRecipient,
        notify_time: notifyTime,
        enabled: enabled,
        include_fields: isFimCreate ? [] : includeFields
    };

    // Attach FIM fields when applicable
    if (isFimCreate) {
        alertData.fim_agent_names = document.getElementById('fim-agent-names').value
            .split(',').map(s => s.trim()).filter(Boolean);
        alertData.fim_paths = document.getElementById('fim-paths').value
            .split(',').map(s => s.trim()).filter(Boolean);
        const fnVal = document.getElementById('fim-file-names').value.trim();
        if (fnVal) alertData.fim_file_names = fnVal.split(',').map(s => s.trim()).filter(Boolean);
        const exVal = document.getElementById('fim-file-extensions').value.trim();
        if (exVal) alertData.fim_file_extensions = exVal.split(',').map(s => s.trim()).filter(Boolean);
    }

    // Show loading modal (reuse existing instance to avoid Bootstrap conflicts)
    const loadingModalEl = document.getElementById('loading-modal');
    const loadingModal = bootstrap.Modal.getOrCreateInstance(loadingModalEl);
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
            // Wait for loading modal to fully close before proceeding
            loadingModalEl.addEventListener('hidden.bs.modal', function onHidden() {
                loadingModalEl.removeEventListener('hidden.bs.modal', onHidden);

                // Reset form
                document.getElementById('create-alert-form').reset();

                // Hide the create modal
                const createModal = bootstrap.Modal.getInstance(document.getElementById('create-alert-modal'));
                if (createModal) {
                    createModal.hide();
                }

                // Reload alert configs
                loadAlertConfigs();

                // Show success message
                showSuccessMessage(data.message || 'Alert configuration created successfully!');
            });
            loadingModal.hide();
        })
        .catch(error => {
            console.error('Error creating alert:', error);
            loadingModalEl.addEventListener('hidden.bs.modal', function onHidden() {
                loadingModalEl.removeEventListener('hidden.bs.modal', onHidden);
                showErrorMessage(`Error creating alert: ${error.message}`);
            });
            loadingModal.hide();
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

    // Determine alert type (edit modal)
    const editTypeRadio = document.querySelector('input[name="edit-alert-type"]:checked');
    const editAlertType = editTypeRadio ? editTypeRadio.value : 'standard';
    const isFimEdit = editAlertType === 'fim';

    // Get selected alert levels (standard only)
    const alertLevels = [];
    document.querySelectorAll('input[name="edit-alert-level"]:checked').forEach(checkbox => {
        alertLevels.push(checkbox.value);
    });

    // Get selected include fields (standard only)
    const includeFields = [];
    document.querySelectorAll('input[name="edit-include-field"]:checked').forEach(checkbox => {
        includeFields.push(checkbox.value);
    });

    // Validate
    if (!alertName) {
        alert('Please enter an alert name');
        return;
    }

    if (!isFimEdit && alertLevels.length === 0) {
        alert('Please select at least one alert level');
        return;
    }

    if (!emailRecipient) {
        alert('Please enter an email recipient');
        return;
    }

    if (!isFimEdit && includeFields.length === 0) {
        alert('Please select at least one field to include in alerts');
        return;
    }

    // FIM-specific validation
    if (isFimEdit) {
        const fimAgents = document.getElementById('edit-fim-agent-names').value.trim();
        const fimPaths  = document.getElementById('edit-fim-paths').value.trim();
        if (!fimAgents) { alert('FIM Alert requires at least one agent name.'); return; }
        if (!fimPaths)  { alert('FIM Alert requires at least one monitored path.'); return; }
    }

    // Build alert data payload
    const alertData = {
        name: alertName,
        alert_type: editAlertType,
        alert_levels: isFimEdit ? [] : alertLevels,
        email_recipient: emailRecipient,
        notify_time: notifyTime,
        enabled: enabled,
        include_fields: isFimEdit ? [] : includeFields
    };

    // Attach FIM fields when applicable
    if (isFimEdit) {
        alertData.fim_agent_names = document.getElementById('edit-fim-agent-names').value
            .split(',').map(s => s.trim()).filter(Boolean);
        alertData.fim_paths = document.getElementById('edit-fim-paths').value
            .split(',').map(s => s.trim()).filter(Boolean);
        const fnVal = (document.getElementById('edit-fim-file-names') || {}).value || '';
        if (fnVal.trim()) alertData.fim_file_names = fnVal.split(',').map(s => s.trim()).filter(Boolean);
        const exVal = (document.getElementById('edit-fim-file-extensions') || {}).value || '';
        if (exVal.trim()) alertData.fim_file_extensions = exVal.split(',').map(s => s.trim()).filter(Boolean);
    }

    // Show loading modal (reuse existing instance to avoid Bootstrap conflicts)
    const loadingModalEl = document.getElementById('loading-modal');
    const loadingModal = bootstrap.Modal.getOrCreateInstance(loadingModalEl);
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
            // Dismiss loading modal immediately
            loadingModal.hide();

            // Close the edit modal immediately (don't wait for loading modal animation)
            const editModal = bootstrap.Modal.getInstance(document.getElementById('edit-alert-modal'));
            if (editModal) editModal.hide();

            // Reload list and show success in parallel — no sequential waits
            loadAlertConfigs();
            showSuccessMessage(data.message || 'Alert configuration updated successfully!');
        })
        .catch(error => {
            console.error('Error updating alert:', error);
            loadingModal.hide();
            showErrorMessage(`Error updating alert: ${error.message}`);
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
 * Refresh alerts table — preserves current page
 */
function refreshAlertsTable() {
    loadSecurityAlerts(currentPage);
}