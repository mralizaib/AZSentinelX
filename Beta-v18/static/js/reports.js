/**
 * Reports JavaScript - AZ Sentinel X
 * Handles report configuration, generation and scheduling
 */

/**
 * Normalize time format to ensure 24-hour HH:MM format
 */
function normalizeTimeFormat(timeStr) {
    if (!timeStr) return null;
    
    // Remove any AM/PM indicators and convert to 24-hour format
    timeStr = timeStr.replace(/\s*(AM|PM|am|pm)\s*/g, '');
    
    // Check if it matches HH:MM pattern
    const timeRegex = /^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$/;
    const match = timeStr.match(timeRegex);
    
    if (match) {
        const hours = parseInt(match[1]);
        const minutes = parseInt(match[2]);
        return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}`;
    }
    
    return null;
}

/**
 * Validate time is in 24-hour format
 */
function validateTimeFormat(timeStr) {
    const timeRegex = /^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$/;
    return timeRegex.test(timeStr);
}

/**
 * Validate time format (HH:MM in 24-hour format)
 */
function validateTimeFormat(timeString) {
    const timePattern = /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/;
    if (!timePattern.test(timeString)) {
        return false;
    }
    
    const [hours, minutes] = timeString.split(':').map(Number);
    return hours >= 0 && hours <= 23 && minutes >= 0 && minutes <= 59;
}

document.addEventListener('DOMContentLoaded', function() {
    // Load report configurations
    loadReportConfigs();
    
    // Set up event listeners
    const createReportForm = document.getElementById('create-report-form');
    if (createReportForm) {
        createReportForm.addEventListener('submit', handleCreateReport);
    }
    
    // Add time format validation to time inputs
    const timeInputs = document.querySelectorAll('#schedule-time, #edit-schedule-time');
    timeInputs.forEach(input => {
        input.addEventListener('blur', function() {
            if (this.value && !validateTimeFormat(this.value)) {
                alert('Please enter time in 24-hour format (HH:MM). Example: 13:30 for 1:30 PM, 20:50 for 8:50 PM');
                this.focus();
            }
        });
        
        // Add input formatting on keypress
        input.addEventListener('input', function(e) {
            let value = e.target.value.replace(/[^\d:]/g, '');
            if (value.length === 2 && !value.includes(':')) {
                value += ':';
            }
            if (value.length > 5) {
                value = value.slice(0, 5);
            }
            e.target.value = value;
        });
    });
    
    const reportFormatSelect = document.getElementById('report-format');
    if (reportFormatSelect) {
        reportFormatSelect.addEventListener('change', function() {
            const previewOption = document.getElementById('preview-option');
            if (previewOption) {
                // Enable preview for HTML format only
                previewOption.disabled = this.value !== 'html';
                if (this.value !== 'html') {
                    previewOption.checked = false;
                }
            }
        });
    }
    
    // Generate report button
    const generateReportBtn = document.getElementById('generate-report-btn');
    if (generateReportBtn) {
        generateReportBtn.addEventListener('click', handleGenerateReport);
    }
});

/**
 * Load report configurations from the API
 */
function loadReportConfigs() {
    const reportsTable = document.getElementById('reports-table-body');
    if (!reportsTable) return;
    
    // Show loading indicator
    reportsTable.innerHTML = `
        <tr>
            <td colspan="7" class="text-center">
                <div class="d-flex justify-content-center">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                </div>
            </td>
        </tr>
    `;
    
    fetch('/api/reports')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(reports => {
            displayReports(reports, reportsTable);
        })
        .catch(error => {
            console.error('Error loading reports:', error);
            reportsTable.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center">
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            Error loading reports: ${error.message}
                        </div>
                    </td>
                </tr>
            `;
        });
}

/**
 * Display reports in the table
 */
function displayReports(reports, container) {
    // Clear container
    container.innerHTML = '';
    
    if (!reports || reports.length === 0) {
        container.innerHTML = `
            <tr>
                <td colspan="7" class="text-center">
                    <div class="alert alert-info">
                        No report configurations found. Create one to get started.
                    </div>
                </td>
            </tr>
        `;
        return;
    }
    
    // Loop through reports and create table rows
    reports.forEach(report => {
        const row = document.createElement('tr');
        
        // Format severity levels
        const levels = report.severity_levels.map(level => 
            `<span class="badge bg-severity-${level}">${level.charAt(0).toUpperCase() + level.slice(1)}</span>`
        ).join(' ');
        
        // Format recipients
        const recipients = report.recipients.join(', ');
        
        // Format created date
        const createdDate = new Date(report.created_at).toLocaleString();
        
        row.innerHTML = `
            <td>${report.name}</td>
            <td>${levels}</td>
            <td>${report.format.toUpperCase()}</td>
            <td>${report.schedule || 'Manual'}</td>
            <td>${recipients}</td>
            <td>${report.enabled ? '<span class="badge bg-success">Enabled</span>' : '<span class="badge bg-danger">Disabled</span>'}</td>
            <td>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-primary btn-generate" data-id="${report.id}" title="Generate Report">
                        <i class="fas fa-file-alt"></i>
                    </button>
                    <button class="btn btn-info btn-send" data-id="${report.id}" title="Send Report">
                        <i class="fas fa-paper-plane"></i>
                    </button>
                    <button class="btn btn-warning btn-edit" data-id="${report.id}" title="Edit Report">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-danger btn-delete" data-id="${report.id}" title="Delete Report">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        
        container.appendChild(row);
    });
    
    // Add event listeners to buttons
    addReportButtonListeners();
}

/**
 * Add event listeners to report action buttons
 */
function addReportButtonListeners() {
    // Generate report buttons
    document.querySelectorAll('.btn-generate').forEach(button => {
        button.addEventListener('click', function() {
            const reportId = this.getAttribute('data-id');
            generateReport(reportId);
        });
    });
    
    // Send report buttons
    document.querySelectorAll('.btn-send').forEach(button => {
        button.addEventListener('click', function() {
            const reportId = this.getAttribute('data-id');
            sendReport(reportId);
        });
    });
    
    // Edit report buttons
    document.querySelectorAll('.btn-edit').forEach(button => {
        button.addEventListener('click', function() {
            const reportId = this.getAttribute('data-id');
            editReport(reportId);
        });
    });
    
    // Delete report buttons
    document.querySelectorAll('.btn-delete').forEach(button => {
        button.addEventListener('click', function() {
            const reportId = this.getAttribute('data-id');
            deleteReport(reportId);
        });
    });
}

/**
 * Generate report for a specific configuration
 */
function generateReport(reportId) {
    // Show loading modal
    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();
    
    fetch(`/api/reports/${reportId}/generate`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            
            // Check if it's HTML or PDF
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return response.json().then(data => {
                    loadingModal.hide();
                    showHtmlReport(data.html);
                });
            } else {
                // It's a PDF, trigger download
                return response.blob().then(blob => {
                    loadingModal.hide();
                    
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    a.download = `security_report_${new Date().toISOString().replace(/[:.]/g, '-')}.pdf`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                });
            }
        })
        .catch(error => {
            console.error('Error generating report:', error);
            loadingModal.hide();
            
            // Show error message
            const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = `Error generating report: ${error.message}`;
            }
            errorModal.show();
        });
}

/**
 * Display HTML report in a modal
 */
function showHtmlReport(html) {
    const reportModal = document.getElementById('report-preview-modal');
    const reportContent = document.getElementById('report-preview-content');
    
    if (reportContent) {
        reportContent.innerHTML = html;
    }
    
    const modal = new bootstrap.Modal(reportModal);
    modal.show();
}

/**
 * Send a report by email
 */
function sendReport(reportId) {
    // Show confirmation dialog
    if (!confirm('Are you sure you want to send this report by email?')) {
        return;
    }
    
    // Show loading modal
    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();
    
    fetch(`/api/reports/${reportId}/send`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || `HTTP error! Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            loadingModal.hide();
            
            // Show success message
            const successModal = new bootstrap.Modal(document.getElementById('success-modal'));
            const successMessage = document.getElementById('success-message');
            if (successMessage) {
                successMessage.textContent = data.message || 'Report sent successfully!';
            }
            successModal.show();
        })
        .catch(error => {
            console.error('Error sending report:', error);
            loadingModal.hide();
            
            // Show error message
            const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = `Error sending report: ${error.message}`;
            }
            errorModal.show();
        });
}

/**
 * Edit an existing report configuration
 */
function editReport(reportId) {
    // Show loading modal
    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();
    
    // Fetch the report configuration
    fetch('/api/reports')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(reports => {
            const report = reports.find(r => r.id.toString() === reportId.toString());
            if (!report) {
                throw new Error('Report not found');
            }
            
            loadingModal.hide();
            
            // Populate the form
            const form = document.getElementById('edit-report-form');
            if (!form) return;
            
            document.getElementById('edit-report-id').value = report.id;
            document.getElementById('edit-report-name').value = report.name;
            
            // Set severity checkboxes
            const severityCheckboxes = document.querySelectorAll('input[name="edit-severity-level"]');
            severityCheckboxes.forEach(checkbox => {
                checkbox.checked = report.severity_levels.includes(checkbox.value);
            });
            
            // Set format
            document.getElementById('edit-report-format').value = report.format;
            
            // Set schedule
            document.getElementById('edit-report-schedule').value = report.schedule || '';
            document.getElementById('edit-schedule-time').value = report.schedule_time || '';
            
            // Set recipients
            document.getElementById('edit-recipients').value = report.recipients.join(', ');
            
            // Set enabled status
            document.getElementById('edit-report-enabled').checked = report.enabled;
            
            // Show the modal
            const editModal = new bootstrap.Modal(document.getElementById('edit-report-modal'));
            editModal.show();
        })
        .catch(error => {
            console.error('Error loading report for editing:', error);
            loadingModal.hide();
            
            // Show error message
            const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = `Error loading report: ${error.message}`;
            }
            errorModal.show();
        });
    
    // Set up form submit handler if not already set
    const editForm = document.getElementById('edit-report-form');
    if (editForm && !editForm.hasAttribute('data-handler-attached')) {
        editForm.setAttribute('data-handler-attached', 'true');
        editForm.addEventListener('submit', handleEditReport);
    }
}

/**
 * Delete a report configuration
 */
function deleteReport(reportId) {
    // Show confirmation dialog
    if (!confirm('Are you sure you want to delete this report configuration?')) {
        return;
    }
    
    fetch(`/api/reports/${reportId}`, {
        method: 'DELETE'
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || `HTTP error! Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            // Reload reports
            loadReportConfigs();
            
            // Show success message
            const successModal = new bootstrap.Modal(document.getElementById('success-modal'));
            const successMessage = document.getElementById('success-message');
            if (successMessage) {
                successMessage.textContent = data.message || 'Report deleted successfully!';
            }
            successModal.show();
        })
        .catch(error => {
            console.error('Error deleting report:', error);
            
            // Show error message
            const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = `Error deleting report: ${error.message}`;
            }
            errorModal.show();
        });
}

/**
 * Handle create report form submission
 */
function handleCreateReport(event) {
    event.preventDefault();
    
    // Get form values
    const reportName = document.getElementById('report-name').value;
    const reportFormat = document.getElementById('report-format').value;
    const schedule = document.getElementById('report-schedule').value;
    let scheduleTime = document.getElementById('schedule-time').value;
    const recipients = document.getElementById('recipients').value.split(',').map(email => email.trim());
    const enabled = document.getElementById('report-enabled').checked;
    
    // Validate and normalize time format to HH:MM
    if (scheduleTime) {
        scheduleTime = normalizeTimeFormat(scheduleTime);
        if (!scheduleTime) {
            alert('Please enter a valid time in 24-hour format (HH:MM)');
            return;
        }
    }
    
    // Get selected severity levels
    const severityLevels = [];
    document.querySelectorAll('input[name="severity-level"]:checked').forEach(checkbox => {
        severityLevels.push(checkbox.value);
    });
    
    // Validate
    if (!reportName) {
        alert('Please enter a report name');
        return;
    }
    
    if (severityLevels.length === 0) {
        alert('Please select at least one severity level');
        return;
    }
    
    if (recipients.length === 0 || recipients[0] === '') {
        alert('Please enter at least one recipient email');
        return;
    }
    
    // Create report data
    const reportData = {
        name: reportName,
        severity_levels: severityLevels,
        format: reportFormat,
        schedule: schedule,
        schedule_time: scheduleTime,
        recipients: recipients,
        enabled: enabled
    };
    
    // Show loading modal
    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();
    
    // Submit to API
    fetch('/api/reports', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(reportData)
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || `HTTP error! Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            loadingModal.hide();
            
            // Reset form
            document.getElementById('create-report-form').reset();
            
            // Hide the modal
            const createModal = bootstrap.Modal.getInstance(document.getElementById('create-report-modal'));
            if (createModal) {
                createModal.hide();
            }
            
            // Reload reports
            loadReportConfigs();
            
            // Show success message
            const successModal = new bootstrap.Modal(document.getElementById('success-modal'));
            const successMessage = document.getElementById('success-message');
            if (successMessage) {
                successMessage.textContent = data.message || 'Report created successfully!';
            }
            successModal.show();
        })
        .catch(error => {
            console.error('Error creating report:', error);
            loadingModal.hide();
            
            // Show error message
            const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = `Error creating report: ${error.message}`;
            }
            errorModal.show();
        });
}

/**
 * Handle edit report form submission
 */
function handleEditReport(event) {
    event.preventDefault();
    
    // Get form values
    const reportId = document.getElementById('edit-report-id').value;
    const reportName = document.getElementById('edit-report-name').value;
    const reportFormat = document.getElementById('edit-report-format').value;
    const schedule = document.getElementById('edit-report-schedule').value;
    const scheduleTime = document.getElementById('edit-schedule-time').value;
    const recipients = document.getElementById('edit-recipients').value.split(',').map(email => email.trim());
    const enabled = document.getElementById('edit-report-enabled').checked;
    
    // Get selected severity levels
    const severityLevels = [];
    document.querySelectorAll('input[name="edit-severity-level"]:checked').forEach(checkbox => {
        severityLevels.push(checkbox.value);
    });
    
    // Validate
    if (!reportName) {
        alert('Please enter a report name');
        return;
    }
    
    if (severityLevels.length === 0) {
        alert('Please select at least one severity level');
        return;
    }
    
    if (recipients.length === 0 || recipients[0] === '') {
        alert('Please enter at least one recipient email');
        return;
    }
    
    // Create report data
    const reportData = {
        name: reportName,
        severity_levels: severityLevels,
        format: reportFormat,
        schedule: schedule,
        schedule_time: scheduleTime,
        recipients: recipients,
        enabled: enabled
    };
    
    // Show loading modal
    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();
    
    // Submit to API
    fetch(`/api/reports/${reportId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(reportData)
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || `HTTP error! Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            loadingModal.hide();
            
            // Hide the modal
            const editModal = bootstrap.Modal.getInstance(document.getElementById('edit-report-modal'));
            if (editModal) {
                editModal.hide();
            }
            
            // Reload reports
            loadReportConfigs();
            
            // Show success message
            const successModal = new bootstrap.Modal(document.getElementById('success-modal'));
            const successMessage = document.getElementById('success-message');
            if (successMessage) {
                successMessage.textContent = data.message || 'Report updated successfully!';
            }
            successModal.show();
        })
        .catch(error => {
            console.error('Error updating report:', error);
            loadingModal.hide();
            
            // Show error message
            const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = `Error updating report: ${error.message}`;
            }
            errorModal.show();
        });
}

/**
 * Show HTML report in preview modal
 */
function showHtmlReport(html) {
    const previewModal = new bootstrap.Modal(document.getElementById('report-preview-modal'));
    const previewContent = document.getElementById('report-preview-content');
    if (previewContent) {
        previewContent.innerHTML = html;
    }
    
    // Set up download button
    const downloadBtn = document.getElementById('download-report-btn');
    if (downloadBtn) {
        downloadBtn.onclick = function() {
            const blob = new Blob([html], { type: 'text/html' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = `security_report_${new Date().toISOString().replace(/[:.]/g, '-')}.html`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
        };
    }
    
    previewModal.show();
}

/**
 * Handle generating a custom report
 */
function handleGenerateReport() {
    // Get form values
    const severityLevels = [];
    document.querySelectorAll('input[name="generate-severity-level"]:checked').forEach(checkbox => {
        severityLevels.push(checkbox.value);
    });
    
    const timeRange = document.getElementById('quick-time-range').value;
    const format = document.getElementById('quick-format').value;
    const preview = document.getElementById('preview-option') && document.getElementById('preview-option').checked;
    
    // Validate
    if (severityLevels.length === 0) {
        alert('Please select at least one severity level');
        return;
    }
    
    // Create report data
    const reportData = {
        severity_levels: severityLevels,
        time_range: timeRange,
        format: format
    };
    
    // Show loading modal
    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();
    
    // Submit to API
    fetch('/api/reports/generate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(reportData)
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || `HTTP error! Status: ${response.status}`);
                });
            }
            
            // Check if it's HTML or PDF
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return response.json().then(data => {
                    loadingModal.hide();
                    
                    if (data.html && preview) {
                        showHtmlReport(data.html);
                    } else {
                        // Download HTML as file
                        const blob = new Blob([data.html], { type: 'text/html' });
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.style.display = 'none';
                        a.href = url;
                        a.download = `security_report_${new Date().toISOString().replace(/[:.]/g, '-')}.html`;
                        document.body.appendChild(a);
                        a.click();
                        window.URL.revokeObjectURL(url);
                    }
                });
            } else {
                // It's a PDF, trigger download
                return response.blob().then(blob => {
                    loadingModal.hide();
                    
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    a.download = `security_report_${new Date().toISOString().replace(/[:.]/g, '-')}.pdf`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                });
            }
        })
        .catch(error => {
            console.error('Error generating report:', error);
            loadingModal.hide();
            
            // Show error message
            const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = `Error generating report: ${error.message}`;
            }
            errorModal.show();
        });
}
