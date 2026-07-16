/**
 * Users JavaScript - AZ Sentinel X
 * Handles user management and module-permission assignment for administrators.
 */

document.addEventListener('DOMContentLoaded', function () {
    if (document.getElementById('users-table')) {
        loadUsers();

        const createUserForm = document.getElementById('create-user-form');
        if (createUserForm) {
            createUserForm.addEventListener('submit', handleCreateUser);
        }

        // Show role hint under the role selector when creating a user
        const roleSelect = document.getElementById('role');
        const roleHint = document.getElementById('role-hint');
        if (roleSelect && roleHint) {
            const updateHint = () => {
                roleHint.textContent = ROLE_HINTS[roleSelect.value] || '';
            };
            roleSelect.addEventListener('change', updateHint);
            updateHint();
        }

        // Show warning when changing role in the edit modal
        const editRoleSelect = document.getElementById('edit-role');
        const editRoleHint = document.getElementById('edit-role-hint');
        if (editRoleSelect && editRoleHint) {
            let originalRole = '';
            document.getElementById('edit-user-modal').addEventListener('show.bs.modal', () => {
                originalRole = editRoleSelect.value;
            });
            editRoleSelect.addEventListener('change', () => {
                editRoleHint.style.display = (editRoleSelect.value !== originalRole) ? '' : 'none';
            });
        }

        // Permissions modal — Select All / Clear All buttons
        document.getElementById('perm-select-all')?.addEventListener('click', () => {
            document.querySelectorAll('#permissions-grid input[type=checkbox]').forEach(cb => cb.checked = true);
        });
        document.getElementById('perm-select-none')?.addEventListener('click', () => {
            document.querySelectorAll('#permissions-grid input[type=checkbox]').forEach(cb => cb.checked = false);
        });
        document.getElementById('save-permissions-btn')?.addEventListener('click', savePermissions);
    }

    // Profile page password validation
    const profileForm = document.getElementById('profile-form');
    if (profileForm) {
        profileForm.addEventListener('submit', function (event) {
            const newPassword = document.getElementById('new-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            if (newPassword && newPassword !== confirmPassword) {
                event.preventDefault();
                alert('New passwords do not match!');
            }
        });
    }
});

// ---------------------------------------------------------------------------
// Load & display users
// ---------------------------------------------------------------------------

function loadUsers() {
    const usersTable = document.getElementById('users-table-body');
    if (!usersTable) return;

    usersTable.innerHTML = `
        <tr>
            <td colspan="6" class="text-center">
                <div class="d-flex justify-content-center">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading…</span>
                    </div>
                </div>
            </td>
        </tr>`;

    fetch('/api/users')
        .then(r => r.ok ? r.json() : r.json().then(d => { throw new Error(d.error || `HTTP ${r.status}`); }))
        .then(users => displayUsers(users, usersTable))
        .catch(err => {
            usersTable.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center">
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-triangle me-2"></i>Error loading users: ${err.message}
                        </div>
                    </td>
                </tr>`;
        });
}

function displayUsers(users, container) {
    container.innerHTML = '';

    if (!users || users.length === 0) {
        container.innerHTML = `
            <tr>
                <td colspan="6" class="text-center">
                    <div class="alert alert-info">No users found.</div>
                </td>
            </tr>`;
        return;
    }

    const currentUserId = document.body.getAttribute('data-user-id');

    users.forEach(user => {
        const row = document.createElement('tr');
        const isCurrentUser = currentUserId && user.id.toString() === currentUserId.toString();
        const createdDate = new Date(user.created_at).toLocaleString();

        let permBadge;
        if (user.is_admin) {
            permBadge = '<span class="badge bg-success">All modules</span>';
        } else if (user.permissions && user.permissions.length > 0) {
            permBadge = `<span class="text-muted small">${user.permissions.length} module(s)</span>`;
        } else {
            permBadge = '<span class="badge bg-secondary">None</span>';
        }

        const permBtn = !user.is_admin
            ? `<button class="btn btn-info btn-sm btn-permissions text-white" data-id="${user.id}" data-username="${user.username}" title="Edit Permissions">
                    <i class="fas fa-key"></i>
               </button>`
            : '';

        const deleteBtn = !isCurrentUser
            ? `<button class="btn btn-danger btn-sm btn-delete" data-id="${user.id}" title="Delete User">
                    <i class="fas fa-trash"></i>
               </button>`
            : '';

        row.innerHTML = `
            <td>${user.username}${isCurrentUser ? ' <span class="badge bg-primary">You</span>' : ''}</td>
            <td>${user.email}</td>
            <td><span class="badge bg-${getRoleColor(user.role)}">${getRoleLabel(user.role)}</span></td>
            <td>${permBadge}</td>
            <td>${createdDate}</td>
            <td>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-warning btn-edit" data-id="${user.id}" title="Edit User">
                        <i class="fas fa-edit"></i>
                    </button>
                    ${permBtn}
                    ${deleteBtn}
                </div>
            </td>`;

        container.appendChild(row);
    });

    addUserButtonListeners();
}

function addUserButtonListeners() {
    document.querySelectorAll('.btn-edit').forEach(btn => {
        btn.addEventListener('click', () => editUser(btn.dataset.id));
    });
    document.querySelectorAll('.btn-delete').forEach(btn => {
        btn.addEventListener('click', () => deleteUser(btn.dataset.id));
    });
    document.querySelectorAll('.btn-permissions').forEach(btn => {
        btn.addEventListener('click', () => editPermissions(btn.dataset.id, btn.dataset.username));
    });
}

// ---------------------------------------------------------------------------
// Edit user
// ---------------------------------------------------------------------------

function editUser(userId) {
    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();

    fetch('/api/users')
        .then(r => r.ok ? r.json() : r.json().then(d => { throw new Error(d.error || `HTTP ${r.status}`); }))
        .then(users => {
            const user = users.find(u => u.id.toString() === userId.toString());
            if (!user) throw new Error('User not found');
            loadingModal.hide();

            document.getElementById('edit-user-id').value = user.id;
            document.getElementById('edit-username').value = user.username;
            document.getElementById('edit-email').value = user.email;
            document.getElementById('edit-role').value = user.role;
            document.getElementById('edit-password').value = '';
            document.getElementById('edit-confirm-password').value = '';

            new bootstrap.Modal(document.getElementById('edit-user-modal')).show();
        })
        .catch(err => {
            loadingModal.hide();
            showError(`Error loading user: ${err.message}`);
        });

    const editForm = document.getElementById('edit-user-form');
    if (editForm && !editForm.hasAttribute('data-handler-attached')) {
        editForm.setAttribute('data-handler-attached', 'true');
        editForm.addEventListener('submit', handleEditUser);
    }
}

// ---------------------------------------------------------------------------
// Delete user
// ---------------------------------------------------------------------------

function deleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;

    fetch(`/api/users/${userId}`, { method: 'DELETE' })
        .then(r => r.ok ? r.json() : r.json().then(d => { throw new Error(d.error || `HTTP ${r.status}`); }))
        .then(data => {
            loadUsers();
            showSuccess(data.message || 'User deleted successfully!');
        })
        .catch(err => showError(`Error deleting user: ${err.message}`));
}

// ---------------------------------------------------------------------------
// Create user
// ---------------------------------------------------------------------------

function handleCreateUser(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    const role = document.getElementById('role').value;

    if (!username || !email || !password) { alert('Please fill in all required fields'); return; }
    if (password !== confirmPassword) { alert('Passwords do not match'); return; }

    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();

    fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password, role }),
    })
        .then(r => r.ok ? r.json() : r.json().then(d => { throw new Error(d.error || `HTTP ${r.status}`); }))
        .then(data => {
            loadingModal.hide();
            document.getElementById('create-user-form').reset();
            bootstrap.Modal.getInstance(document.getElementById('create-user-modal'))?.hide();
            loadUsers();
            showSuccess(data.message || 'User created successfully!');
        })
        .catch(err => {
            loadingModal.hide();
            showError(`Error creating user: ${err.message}`);
        });
}

// ---------------------------------------------------------------------------
// Edit user submit
// ---------------------------------------------------------------------------

function handleEditUser(event) {
    event.preventDefault();

    const userId = document.getElementById('edit-user-id').value;
    const email = document.getElementById('edit-email').value;
    const password = document.getElementById('edit-password').value;
    const confirmPassword = document.getElementById('edit-confirm-password').value;
    const role = document.getElementById('edit-role').value;

    if (!email) { alert('Please enter an email'); return; }
    if (password && password !== confirmPassword) { alert('Passwords do not match'); return; }

    const userData = { email, role };
    if (password) userData.password = password;

    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();

    fetch(`/api/users/${userId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData),
    })
        .then(r => r.ok ? r.json() : r.json().then(d => { throw new Error(d.error || `HTTP ${r.status}`); }))
        .then(data => {
            loadingModal.hide();
            bootstrap.Modal.getInstance(document.getElementById('edit-user-modal'))?.hide();
            loadUsers();
            showSuccess(data.message || 'User updated successfully!');
        })
        .catch(err => {
            loadingModal.hide();
            showError(`Error updating user: ${err.message}`);
        });
}

// ---------------------------------------------------------------------------
// Permission management
// ---------------------------------------------------------------------------

// Role definitions — must match VALID_ROLES in routes/users.py
const ROLE_OPTIONS = [
    { value: 'viewer',      label: 'Viewer',         color: 'secondary' },
    { value: 'soc_analyst', label: 'SOC Analyst',    color: 'primary' },
    { value: 'dpcm',        label: 'DPCM',           color: 'info text-dark' },
    { value: 'admin',       label: 'Administrator',  color: 'danger' },
];

const ROLE_HINTS = {
    viewer:      'Dashboard, Alerts, Reports',
    soc_analyst: 'Dashboard, Alerts, AI Insights, Reports, Threat Intel, Config Assessment, Integrations',
    dpcm:        'Full DVR/NVR Configuration Management only (Single Device, Bulk, Camera Names, Templates, Reports, History) — no access to any other module',
    admin:       'Full access to all modules and admin settings',
};

function getRoleLabel(role) {
    const r = ROLE_OPTIONS.find(o => o.value === role);
    return r ? r.label : role;
}

function getRoleColor(role) {
    const r = ROLE_OPTIONS.find(o => o.value === role);
    return r ? r.color : 'info';
}

// Labels matching MODULE_PERMISSIONS keys defined on the server
const PERM_LABELS = {
    dashboard:         'Dashboard',
    alerts:            'Alerts',
    ai_insights:       'AI Insights',
    reports:           'Reports',
    threat_intel:      'Threat Intelligence',
    config_assessment: 'Config Assessment',
    integrations:      'Integrations',
    dvr_config:        'DVR Configuration',
    dvr_bulk:          'Bulk DVR Configuration',
    storage:           'Storage Management',
    retention:         'Data Retention',
};

const PERM_ICONS = {
    dashboard:         'fa-gauge-high',
    alerts:            'fa-shield-halved',
    ai_insights:       'fa-microchip',
    reports:           'fa-file-shield',
    threat_intel:      'fa-binoculars',
    config_assessment: 'fa-shield-halved',
    integrations:      'fa-network-wired',
    dvr_config:        'fa-video',
    dvr_bulk:          'fa-layer-group',
    storage:           'fa-server',
    retention:         'fa-database',
};

function editPermissions(userId, username) {
    document.getElementById('perm-user-id').value = userId;
    document.getElementById('perm-username').textContent = username;
    document.getElementById('permissions-loading').style.display = '';
    document.getElementById('permissions-grid').style.display = 'none';

    new bootstrap.Modal(document.getElementById('permissions-modal')).show();

    fetch(`/api/users/${userId}/permissions`)
        .then(r => r.ok ? r.json() : r.json().then(d => { throw new Error(d.error || `HTTP ${r.status}`); }))
        .then(data => {
            renderPermissionsGrid(data.permissions || [], data.all_permissions || PERM_LABELS);
            document.getElementById('permissions-loading').style.display = 'none';
            document.getElementById('permissions-grid').style.display = '';
        })
        .catch(err => {
            document.getElementById('permissions-loading').innerHTML =
                `<div class="alert alert-danger">Error loading permissions: ${err.message}</div>`;
        });
}

function renderPermissionsGrid(granted, allPerms) {
    const grid = document.getElementById('permissions-grid');
    grid.innerHTML = '';

    Object.entries(allPerms).forEach(([key, label]) => {
        const icon = PERM_ICONS[key] || 'fa-lock';
        const checked = granted.includes(key) ? 'checked' : '';
        const col = document.createElement('div');
        col.className = 'col-sm-6 col-md-4';
        col.innerHTML = `
            <div class="form-check card p-3 h-100">
                <input class="form-check-input perm-checkbox" type="checkbox" id="perm_${key}" value="${key}" ${checked}>
                <label class="form-check-label fw-semibold" for="perm_${key}">
                    <i class="fas ${icon} me-2 text-primary"></i>${label}
                </label>
            </div>`;
        grid.appendChild(col);
    });
}

function savePermissions() {
    const userId = document.getElementById('perm-user-id').value;
    const selected = [...document.querySelectorAll('.perm-checkbox:checked')].map(cb => cb.value);

    const btn = document.getElementById('save-permissions-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Saving…';

    fetch(`/api/users/${userId}/permissions`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ permissions: selected }),
    })
        .then(r => r.ok ? r.json() : r.json().then(d => { throw new Error(d.error || `HTTP ${r.status}`); }))
        .then(data => {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-save me-1"></i>Save Permissions';
            bootstrap.Modal.getInstance(document.getElementById('permissions-modal'))?.hide();
            loadUsers();
            showSuccess(`Permissions updated for user — ${selected.length} module(s) granted.`);
        })
        .catch(err => {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-save me-1"></i>Save Permissions';
            showError(`Error saving permissions: ${err.message}`);
        });
}

// ---------------------------------------------------------------------------
// Shared modal helpers
// ---------------------------------------------------------------------------

function showSuccess(message) {
    const el = document.getElementById('success-message');
    if (el) el.textContent = message;
    const modal = document.getElementById('success-modal');
    if (modal) new bootstrap.Modal(modal).show();
    else alert(message);
}

function showError(message) {
    const el = document.getElementById('error-message');
    if (el) el.textContent = message;
    const modal = document.getElementById('error-modal');
    if (modal) new bootstrap.Modal(modal).show();
    else alert(message);
}
