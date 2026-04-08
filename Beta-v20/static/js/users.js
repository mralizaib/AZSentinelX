/**
 * Users JavaScript - AZ Sentinel X
 * Handles user management functions for administrators
 */

document.addEventListener('DOMContentLoaded', function() {
    // Load users if on the users page
    if (document.getElementById('users-table')) {
        loadUsers();
        
        // Set up event listener for create user form
        const createUserForm = document.getElementById('create-user-form');
        if (createUserForm) {
            createUserForm.addEventListener('submit', handleCreateUser);
        }
    }
    
    // Set up event listener for profile form
    const profileForm = document.getElementById('profile-form');
    if (profileForm) {
        profileForm.addEventListener('submit', function(event) {
            const newPassword = document.getElementById('new-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            
            if (newPassword && newPassword !== confirmPassword) {
                event.preventDefault();
                alert('New passwords do not match!');
                return false;
            }
        });
    }
});

/**
 * Load users from the API
 */
function loadUsers() {
    const usersTable = document.getElementById('users-table-body');
    if (!usersTable) return;
    
    // Show loading indicator
    usersTable.innerHTML = `
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
    
    fetch('/api/users')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(users => {
            displayUsers(users, usersTable);
        })
        .catch(error => {
            console.error('Error loading users:', error);
            usersTable.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center">
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            Error loading users: ${error.message}
                        </div>
                    </td>
                </tr>
            `;
        });
}

/**
 * Display users in the table
 */
function displayUsers(users, container) {
    // Clear container
    container.innerHTML = '';
    
    if (!users || users.length === 0) {
        container.innerHTML = `
            <tr>
                <td colspan="5" class="text-center">
                    <div class="alert alert-info">
                        No users found.
                    </div>
                </td>
            </tr>
        `;
        return;
    }
    
    // Get current user ID
    const currentUserId = document.body.getAttribute('data-user-id');
    
    // Loop through users and create table rows
    users.forEach(user => {
        const row = document.createElement('tr');
        
        // Format created date
        const createdDate = new Date(user.created_at).toLocaleString();
        
        // Check if this is the current user
        const isCurrentUser = currentUserId && user.id.toString() === currentUserId.toString();
        
        row.innerHTML = `
            <td>${user.username}${isCurrentUser ? ' <span class="badge bg-primary">You</span>' : ''}</td>
            <td>${user.email}</td>
            <td>
                <span class="badge bg-${user.role === 'admin' ? 'danger' : 'info'}">${user.role}</span>
            </td>
            <td>${createdDate}</td>
            <td>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-warning btn-edit" data-id="${user.id}" title="Edit User">
                        <i class="fas fa-edit"></i>
                    </button>
                    ${!isCurrentUser ? `
                        <button class="btn btn-danger btn-delete" data-id="${user.id}" title="Delete User">
                            <i class="fas fa-trash"></i>
                        </button>
                    ` : ''}
                </div>
            </td>
        `;
        
        container.appendChild(row);
    });
    
    // Add event listeners to buttons
    addUserButtonListeners();
}

/**
 * Add event listeners to user action buttons
 */
function addUserButtonListeners() {
    // Edit user buttons
    document.querySelectorAll('.btn-edit').forEach(button => {
        button.addEventListener('click', function() {
            const userId = this.getAttribute('data-id');
            editUser(userId);
        });
    });
    
    // Delete user buttons
    document.querySelectorAll('.btn-delete').forEach(button => {
        button.addEventListener('click', function() {
            const userId = this.getAttribute('data-id');
            deleteUser(userId);
        });
    });
}

/**
 * Edit an existing user
 */
function editUser(userId) {
    // Show loading modal
    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();
    
    // Fetch the user data
    fetch('/api/users')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(users => {
            const user = users.find(u => u.id.toString() === userId.toString());
            if (!user) {
                throw new Error('User not found');
            }
            
            loadingModal.hide();
            
            // Populate the form
            const form = document.getElementById('edit-user-form');
            if (!form) return;
            
            document.getElementById('edit-user-id').value = user.id;
            document.getElementById('edit-username').value = user.username;
            document.getElementById('edit-email').value = user.email;
            
            // Set role
            const roleSelect = document.getElementById('edit-role');
            if (roleSelect) {
                roleSelect.value = user.role;
            }
            
            // Clear password fields
            document.getElementById('edit-password').value = '';
            document.getElementById('edit-confirm-password').value = '';
            
            // Show the modal
            const editModal = new bootstrap.Modal(document.getElementById('edit-user-modal'));
            editModal.show();
        })
        .catch(error => {
            console.error('Error loading user for editing:', error);
            loadingModal.hide();
            
            // Show error message
            const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = `Error loading user: ${error.message}`;
            }
            errorModal.show();
        });
    
    // Set up form submit handler if not already set
    const editForm = document.getElementById('edit-user-form');
    if (editForm && !editForm.hasAttribute('data-handler-attached')) {
        editForm.setAttribute('data-handler-attached', 'true');
        editForm.addEventListener('submit', handleEditUser);
    }
}

/**
 * Delete a user
 */
function deleteUser(userId) {
    // Show confirmation dialog
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
        return;
    }
    
    fetch(`/api/users/${userId}`, {
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
            // Reload users
            loadUsers();
            
            // Show success message
            const successModal = new bootstrap.Modal(document.getElementById('success-modal'));
            const successMessage = document.getElementById('success-message');
            if (successMessage) {
                successMessage.textContent = data.message || 'User deleted successfully!';
            }
            successModal.show();
        })
        .catch(error => {
            console.error('Error deleting user:', error);
            
            // Show error message
            const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = `Error deleting user: ${error.message}`;
            }
            errorModal.show();
        });
}

/**
 * Handle create user form submission
 */
function handleCreateUser(event) {
    event.preventDefault();
    
    // Get form values
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    const role = document.getElementById('role').value;
    
    // Validate
    if (!username) {
        alert('Please enter a username');
        return;
    }
    
    if (!email) {
        alert('Please enter an email');
        return;
    }
    
    if (!password) {
        alert('Please enter a password');
        return;
    }
    
    if (password !== confirmPassword) {
        alert('Passwords do not match');
        return;
    }
    
    // Create user data
    const userData = {
        username: username,
        email: email,
        password: password,
        role: role
    };
    
    // Show loading modal
    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();
    
    // Submit to API
    fetch('/api/users', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
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
            document.getElementById('create-user-form').reset();
            
            // Hide the modal
            const createModal = bootstrap.Modal.getInstance(document.getElementById('create-user-modal'));
            if (createModal) {
                createModal.hide();
            }
            
            // Reload users
            loadUsers();
            
            // Show success message
            const successModal = new bootstrap.Modal(document.getElementById('success-modal'));
            const successMessage = document.getElementById('success-message');
            if (successMessage) {
                successMessage.textContent = data.message || 'User created successfully!';
            }
            successModal.show();
        })
        .catch(error => {
            console.error('Error creating user:', error);
            loadingModal.hide();
            
            // Show error message
            const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = `Error creating user: ${error.message}`;
            }
            errorModal.show();
        });
}

/**
 * Handle edit user form submission
 */
function handleEditUser(event) {
    event.preventDefault();
    
    // Get form values
    const userId = document.getElementById('edit-user-id').value;
    const email = document.getElementById('edit-email').value;
    const password = document.getElementById('edit-password').value;
    const confirmPassword = document.getElementById('edit-confirm-password').value;
    const role = document.getElementById('edit-role').value;
    
    // Validate
    if (!email) {
        alert('Please enter an email');
        return;
    }
    
    if (password && password !== confirmPassword) {
        alert('Passwords do not match');
        return;
    }
    
    // Create user data
    const userData = {
        email: email,
        role: role
    };
    
    // Only include password if it was provided
    if (password) {
        userData.password = password;
    }
    
    // Show loading modal
    const loadingModal = new bootstrap.Modal(document.getElementById('loading-modal'));
    loadingModal.show();
    
    // Submit to API
    fetch(`/api/users/${userId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
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
            const editModal = bootstrap.Modal.getInstance(document.getElementById('edit-user-modal'));
            if (editModal) {
                editModal.hide();
            }
            
            // Reload users
            loadUsers();
            
            // Show success message
            const successModal = new bootstrap.Modal(document.getElementById('success-modal'));
            const successMessage = document.getElementById('success-message');
            if (successMessage) {
                successMessage.textContent = data.message || 'User updated successfully!';
            }
            successModal.show();
        })
        .catch(error => {
            console.error('Error updating user:', error);
            loadingModal.hide();
            
            // Show error message
            const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = `Error updating user: ${error.message}`;
            }
            errorModal.show();
        });
}
