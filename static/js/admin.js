/**
 * Admin Panel JavaScript Module
 * Handles user management and file operations for administrators
 */

import { 
    getCsrfToken, 
    formatBytes, 
    truncateHash, 
    escapeHtml, 
    secureFetch, 
    logout 
} from './utils.js';

// --- Constants ---
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

// --- State ---
let allAccounts = [];
let currentFileId = null;
let currentAccountId = null; // The logged-in admin's account ID

// --- DOM Elements (cached on init) ---
let elements = {};

// =============================================================================
// USER MANAGEMENT
// =============================================================================

/**
 * Fetches and displays all users
 */
async function fetchUsers() {
    try {
        const response = await secureFetch("/api/admin/users");
        if (!response.ok) {
            throw new Error(`Failed to fetch users: ${response.status}`);
        }
        const users = await response.json();
        allAccounts = users; // Store for permission checkboxes
        displayUsers(users);
        renderAccountCheckboxes();
    } catch (error) {
        console.error("Error fetching users:", error);
        showError(error.message);
    }
}

/**
 * Renders user table
 * @param {Array} users - Array of user objects
 */
function displayUsers(users) {
    const tbody = elements.usersTbody;
    const table = elements.usersTable;
    
    if (!tbody || !table) {
        console.error("User table elements not found");
        return;
    }
    
    tbody.innerHTML = '';
    
    if (users.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" style="text-align: center; padding: 20px;">
                    No users found
                </td>
            </tr>
        `;
    } else {
        users.forEach(user => {
            const isSelf = user.id === currentAccountId;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="monospace">${escapeHtml(user.id)}</td>
                <td>${new Date(user.created_at).toLocaleString()}</td>
                <td>
                    <span class="${user.is_verified ? 'status-verified' : 'status-contaminated'}">
                        ${user.is_verified ? 'Verified' : 'Not Verified'}
                    </span>
                </td>
                <td>
                    ${user.is_admin ? '<span class="admin-badge">Admin</span>' : '<span class="user-badge">User</span>'}
                </td>
                <td>
                    <button class="btn-sm btn-red" data-user-id="${escapeHtml(user.id)}" ${isSelf ? 'disabled title="Cannot delete your own account"' : ''}>
                        Delete
                    </button>
                </td>
            `;
            
            // Attach delete handler (only if not self)
            const deleteBtn = tr.querySelector('.btn-red');
            if (!isSelf) {
                deleteBtn.addEventListener('click', () => deleteUser(user.id));
            }
            
            tbody.appendChild(tr);
        });
    }
    
    table.style.display = 'table';
}

/**
 * Deletes a user after confirmation
 * @param {string} accountId - User account ID
 */
async function deleteUser(accountId) {
    // Prevent self-deletion
    if (accountId === currentAccountId) {
        showError("You cannot delete your own account");
        return;
    }
    
    if (!confirm(`Are you sure you want to delete user ${accountId}?`)) {
        return;
    }

    try {
        const response = await secureFetch(`/api/admin/users/${accountId}`, {
            method: "DELETE"
        });

        if (response.ok) {
            await fetchUsers();
        } else {
            const errorText = await response.text();
            throw new Error(`Failed to delete user: ${errorText}`);
        }
    } catch (error) {
        console.error("Error deleting user:", error);
        showError(error.message);
    }
}

// =============================================================================
// FILE MANAGEMENT - UPLOAD
// =============================================================================

/**
 * Renders account checkboxes for upload permissions
 */
function renderAccountCheckboxes() {
    const container = elements.accountCheckboxes;
    if (!container) return;
    
    if (allAccounts.length === 0) {
        container.innerHTML = `
            <div style="padding: 10px; text-align: center;">
                No active accounts found
            </div>
        `;
        return;
    }
    
    container.innerHTML = allAccounts.map(acc => `
        <label class="checkbox-label">
            <input type="checkbox" name="account" value="${escapeHtml(acc.id)}">
            <span class="account-id">${escapeHtml(acc.id)}</span>
            ${acc.is_verified ? '<span class="verified-badge" title="Verified">Verified</span>' : ''}
        </label>
    `).join('');
}

/**
 * Handles file input change - validates size
 * @param {Event} e - Change event
 */
function handleFileInputChange(e) {
    const file = e.target.files[0];
    const info = elements.fileInfo;
    const uploadBtn = elements.uploadBtn;
    
    if (!info || !uploadBtn) return;
    
    if (file) {
        if (file.size > MAX_FILE_SIZE) {
            info.innerHTML = `
                <span class="error-text">
                    File too large (${formatBytes(file.size)}). Maximum size is 50MB.
                </span>
            `;
            uploadBtn.disabled = true;
        } else {
            info.innerHTML = `
                <span class="success-text">
                    Ready: <strong>${escapeHtml(file.name)}</strong> (${formatBytes(file.size)})
                </span>
            `;
            uploadBtn.disabled = false;
        }
    } else {
        info.innerHTML = '';
        uploadBtn.disabled = false;
    }
}

/**
 * Handles file upload form submission
 * Uses FormData for stream-aware upload (doesn't load entire file into RAM)
 * @param {Event} e - Submit event
 */
async function handleUploadSubmit(e) {
    e.preventDefault();
    
    const fileInput = elements.fileInput;
    const file = fileInput?.files[0];
    if (!file) return;

    const feedback = elements.uploadFeedback;
    const progress = elements.uploadProgress;
    const btn = elements.uploadBtn;
    const btnText = elements.uploadBtnText;

    // Get selected accounts
    const selectedAccounts = Array.from(
        document.querySelectorAll('#accountCheckboxes input:checked')
    ).map(cb => cb.value);

    // Prepare FormData (browser handles streaming)
    const formData = new FormData();
    formData.append("file", file);
    formData.append("account_ids", JSON.stringify(selectedAccounts));

    // UI State: Uploading
    if (btn) btn.disabled = true;
    if (btnText) btnText.textContent = 'Uploading...';
    if (progress) progress.style.display = 'block';
    if (feedback) feedback.innerHTML = '';

    try {
        const csrfToken = await getCsrfToken();
        const response = await fetch("/api/admin/files/upload", {
            method: "POST",
            headers: { "X-CSRF-Token": csrfToken },
            body: formData
        });

        const data = await response.json();
        
        if (response.ok) {
            if (feedback) {
                feedback.innerHTML = `
                    <div class="verification-success">
                        <strong>Upload Complete!</strong><br>
                        File ID: <code>${escapeHtml(data.file_id)}</code><br>
                        Integrity Hash: <code class="hash-cell">${truncateHash(data.blake3_hash)}</code>
                        ${data.deduplicated ? '<br><em>Deduplicated (physical storage reused)</em>' : ''}
                    </div>
                `;
            }
            
            // Reset form
            e.target.reset();
            if (elements.fileInfo) elements.fileInfo.innerHTML = '';
            renderAccountCheckboxes();
            
            // Refresh files list
            await fetchFiles();
        } else {
            throw new Error(data.message || data.error || "Upload failed");
        }
    } catch (err) {
        console.error("Upload error:", err);
        if (feedback) {
            feedback.innerHTML = `
                <div class="verification-error">
                    <strong>Upload Failed</strong><br>
                    ${escapeHtml(err.message)}
                </div>
            `;
        }
    } finally {
        if (btn) btn.disabled = false;
        if (btnText) btnText.textContent = 'Upload & Secure';
        if (progress) progress.style.display = 'none';
    }
}

// =============================================================================
// FILE MANAGEMENT - LIST & ACTIONS
// =============================================================================

/**
 * Fetches and displays all files
 */
async function fetchFiles() {
    console.log("Fetching files...");
    try {
        const response = await secureFetch("/api/admin/files");
        console.log("Files response status:", response.status);
        
        if (response.ok) {
            const data = await response.json();
            console.log("Files data received:", data);
            renderFilesTable(data);
        } else {
            console.error("Failed to fetch files:", response.status);
        }
    } catch (e) {
        console.error("Error fetching files:", e);
    }
}

/**
 * Renders the files table
 * Handles multiple response formats:
 * - Array of file objects
 * - Array of {file, permissions} objects
 * @param {Array} data - Array of file data
 */
function renderFilesTable(data) {
    const tbody = elements.filesTbody;
    const table = elements.filesTable;
    const noFiles = elements.noFilesMessage;

    console.log("Rendering files table with data:", data);
    console.log("Elements:", { tbody, table, noFiles });

    if (!tbody || !table) {
        console.error("Files table elements not found");
        return;
    }

    tbody.innerHTML = '';
    
    // Handle empty or invalid data
    if (!data || !Array.isArray(data) || data.length === 0) {
        table.style.display = 'none';
        if (noFiles) noFiles.style.display = 'block';
        return;
    }

    table.style.display = 'table';
    if (noFiles) noFiles.style.display = 'none';

    data.forEach((item, index) => {
        // Handle both formats: {file: {...}, permissions: [...]} or just file object
        const f = item.file || item;
        const permissions = item.permissions || [];
        
        console.log(`Processing file ${index}:`, f);
        
        if (!f || !f.id) {
            console.warn("Invalid file object at index", index, item);
            return;
        }

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${escapeHtml(f.filename || 'Unknown')}</strong></td>
            <td>${escapeHtml(f.file_type || f.mime_type || 'Unknown')}</td>
            <td>${formatBytes(f.file_size || f.size || 0)}</td>
            <td>
                <span class="hash-cell" title="${escapeHtml(f.blake3_hash || '')}">
                    ${truncateHash(f.blake3_hash || '')}
                </span>
            </td>
            <td>${Array.isArray(permissions) ? permissions.length : 0} users</td>
            <td class="actions-cell">
                <button class="btn-sm btn-blue btn-perms">
                    Access
                </button>
                <button class="btn-sm btn-green btn-download">
                    Download
                </button>
                <button class="btn-sm btn-red btn-delete">
                    Delete
                </button>
            </td>
        `;
        
        // Attach event handlers using data attributes stored in closures
        const fileId = f.id;
        const filename = f.filename || 'download';
        
        tr.querySelector('.btn-perms').addEventListener('click', () => {
            openPermissionsModal(fileId, filename);
        });
        tr.querySelector('.btn-download').addEventListener('click', () => {
            downloadFile(fileId, filename);
        });
        tr.querySelector('.btn-delete').addEventListener('click', () => {
            deleteFile(fileId);
        });
        
        tbody.appendChild(tr);
    });
    
    console.log("Files table rendered with", data.length, "rows");
}

/**
 * Downloads a file (admin)
 * @param {string} fileId - File ID
 * @param {string} filename - Original filename
 */
async function downloadFile(fileId, filename) {
    try {
        const response = await secureFetch(`/api/admin/files/${fileId}/download`);
        
        if (!response.ok) {
            throw new Error("Download failed");
        }
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
    } catch (err) {
        console.error("Download error:", err);
        showError("Failed to download file");
    }
}

/**
 * Deletes a file after confirmation
 * @param {string} fileId - File ID
 */
async function deleteFile(fileId) {
    if (!confirm("Delete this file? This action cannot be undone.")) return;
    
    try {
        const response = await secureFetch(`/api/admin/files/${fileId}`, {
            method: "DELETE"
        });
        
        if (response.ok) {
            await fetchFiles();
        } else {
            throw new Error("Delete failed");
        }
    } catch (err) {
        console.error("Delete error:", err);
        showError("Failed to delete file");
    }
}

// =============================================================================
// PERMISSION MODAL
// =============================================================================

/**
 * Opens the permissions modal for a file
 * @param {string} fileId - File ID
 * @param {string} filename - File name for display
 */
async function openPermissionsModal(fileId, filename) {
    currentFileId = fileId;
    
    if (elements.modalFileName) {
        elements.modalFileName.textContent = `File: ${filename}`;
    }
    if (elements.permissionModal) {
        elements.permissionModal.style.display = 'block';
    }
    
    // Fetch current permissions
    try {
        const response = await secureFetch(`/api/admin/files/${fileId}/permissions`);
        let permissions = [];
        
        if (response.ok) {
            permissions = await response.json();
        }
        
        renderModalCheckboxes(permissions);
    } catch (err) {
        console.error("Error fetching permissions:", err);
        if (elements.modalAccountCheckboxes) {
            elements.modalAccountCheckboxes.innerHTML = `
                <div style="color: var(--color-danger); padding: 10px;">
                    Error loading permissions
                </div>
            `;
        }
    }
}

/**
 * Renders checkboxes in the permission modal
 * @param {Array} currentPermissions - Array of permission objects or account IDs
 */
function renderModalCheckboxes(currentPermissions) {
    const container = elements.modalAccountCheckboxes;
    if (!container) return;
    
    // Extract account IDs from permissions (handle different formats)
    const permittedIds = currentPermissions.map(p => {
        if (typeof p === 'string') return p;
        return p.account_id || p.user_id || p.id || p;
    });
    
    console.log("Current permissions:", permittedIds);
    console.log("All accounts:", allAccounts);
    
    if (allAccounts.length === 0) {
        container.innerHTML = `
            <div style="padding: 10px; text-align: center;">
                No accounts available
            </div>
        `;
        return;
    }
    
    container.innerHTML = allAccounts.map(acc => `
        <label class="checkbox-label">
            <input type="checkbox" name="modal-account" value="${escapeHtml(acc.id)}" 
                   ${permittedIds.includes(acc.id) ? 'checked' : ''}>
            <span class="account-id">${escapeHtml(acc.id)}</span>
            ${acc.is_verified ? '<span class="verified-badge" title="Verified">Verified</span>' : ''}
        </label>
    `).join('');
}

/**
 * Saves permission changes
 * Compares current permissions with selected ones and calls grant/revoke endpoints
 */
async function savePermissions() {
    if (!currentFileId) return;
    
    // Get newly selected accounts from modal checkboxes
    const selectedAccounts = Array.from(
        document.querySelectorAll('#modalAccountCheckboxes input:checked')
    ).map(cb => cb.value);
    
    console.log("Saving permissions for file:", currentFileId);
    console.log("Selected accounts:", selectedAccounts);
    
    try {
        // First, get current permissions to compare
        const permResponse = await secureFetch(`/api/admin/files/${currentFileId}/permissions`);
        let currentPermissions = [];
        if (permResponse.ok) {
            currentPermissions = await permResponse.json();
        }
        
        console.log("Current permissions:", currentPermissions);
        
        // Calculate which accounts to grant and which to revoke
        const currentSet = new Set(currentPermissions);
        const selectedSet = new Set(selectedAccounts);
        
        const toGrant = selectedAccounts.filter(id => !currentSet.has(id));
        const toRevoke = currentPermissions.filter(id => !selectedSet.has(id));
        
        console.log("To grant:", toGrant);
        console.log("To revoke:", toRevoke);
        
        // Grant new permissions
        if (toGrant.length > 0) {
            const grantResponse = await secureFetch(`/api/admin/files/${currentFileId}/permissions/grant`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ account_ids: toGrant })
            });
            
            if (!grantResponse.ok) {
                const errorText = await grantResponse.text();
                throw new Error(`Failed to grant permissions: ${errorText}`);
            }
        }
        
        // Revoke removed permissions
        if (toRevoke.length > 0) {
            const revokeResponse = await secureFetch(`/api/admin/files/${currentFileId}/permissions/revoke`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ account_ids: toRevoke })
            });
            
            if (!revokeResponse.ok) {
                const errorText = await revokeResponse.text();
                throw new Error(`Failed to revoke permissions: ${errorText}`);
            }
        }
        
        closeModal();
        await fetchFiles();
    } catch (err) {
        console.error("Error saving permissions:", err);
        showError(err.message || "Failed to save permissions");
    }
}

/**
 * Closes the permission modal
 */
function closeModal() {
    if (elements.permissionModal) {
        elements.permissionModal.style.display = 'none';
    }
    currentFileId = null;
}

// =============================================================================
// UI HELPERS
// =============================================================================

/**
 * Shows an error message
 * @param {string} message - Error message
 */
function showError(message) {
    const errorDiv = elements.usersError;
    if (errorDiv) {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
        setTimeout(() => {
            errorDiv.style.display = 'none';
        }, 5000);
    } else {
        alert(message);
    }
}

/**
 * Toggles all checkboxes in a container
 * @param {string} containerSelector - Container selector
 * @param {boolean} checked - Check state
 */
function toggleAllCheckboxes(containerSelector, checked) {
    document.querySelectorAll(`${containerSelector} input[type="checkbox"]`)
        .forEach(cb => cb.checked = checked);
}

// =============================================================================
// ADMIN ACCESS CHECK & INITIALIZATION
// =============================================================================

/**
 * Checks if current user has admin access
 */
async function checkAdminAccess() {
    try {
        const response = await fetch("/api/admin/check");
        
        if (response.ok) {
            const data = await response.json();
            currentAccountId = data.account_id; // Store current admin's account ID
            
            if (elements.adminView) elements.adminView.style.display = 'block';
            if (elements.accessDenied) elements.accessDenied.style.display = 'none';
            if (elements.fileSection) elements.fileSection.style.display = 'block';
            
            // Initialize admin panel
            await fetchUsers();
            await fetchFiles();
        } else if (response.status === 403) {
            if (elements.adminView) elements.adminView.style.display = 'none';
            if (elements.accessDenied) elements.accessDenied.style.display = 'block';
            if (elements.fileSection) elements.fileSection.style.display = 'none';
        } else {
            window.location.href = '/login.html';
        }
    } catch (error) {
        console.error("Error checking admin access:", error);
        window.location.href = '/login.html';
    }
}

/**
 * Caches DOM element references
 */
function cacheElements() {
    elements = {
        // Views
        adminView: document.getElementById('admin-view'),
        accessDenied: document.getElementById('access-denied'),
        fileSection: document.getElementById('file-management-section'),
        
        // User table
        usersTable: document.getElementById('users-table'),
        usersTbody: document.getElementById('users-tbody'),
        usersError: document.getElementById('users-error'),
        
        // Upload form
        uploadForm: document.getElementById('uploadForm'),
        fileInput: document.getElementById('fileInput'),
        fileInfo: document.getElementById('fileInfo'),
        uploadBtn: document.getElementById('uploadBtn'),
        uploadBtnText: document.getElementById('uploadBtnText'),
        uploadProgress: document.getElementById('uploadProgress'),
        uploadFeedback: document.getElementById('upload-feedback'),
        accountCheckboxes: document.getElementById('accountCheckboxes'),
        
        // Files table
        filesTable: document.getElementById('files-table'),
        filesTbody: document.getElementById('files-tbody'),
        noFilesMessage: document.getElementById('no-files-message'),
        
        // Permission modal
        permissionModal: document.getElementById('permissionModal'),
        modalFileName: document.getElementById('modalFileName'),
        modalAccountCheckboxes: document.getElementById('modalAccountCheckboxes')
    };
    
    console.log("Cached elements:", elements);
}

/**
 * Attaches all event listeners
 */
function attachEventListeners() {
    // Navigation buttons
    document.getElementById('logoutBtn')?.addEventListener('click', logout);
    document.getElementById('backBtn')?.addEventListener('click', () => {
        window.location.href = '/';
    });
    document.getElementById('backBtnDenied')?.addEventListener('click', () => {
        window.location.href = '/';
    });
    
    // User management
    document.getElementById('refreshUsersBtn')?.addEventListener('click', fetchUsers);
    
    // File upload
    if (elements.fileInput) {
        elements.fileInput.addEventListener('change', handleFileInputChange);
    }
    if (elements.uploadForm) {
        elements.uploadForm.addEventListener('submit', handleUploadSubmit);
    }
    
    // Account selection (upload)
    document.getElementById('selectAllAccounts')?.addEventListener('click', () => {
        toggleAllCheckboxes('#accountCheckboxes', true);
    });
    document.getElementById('deselectAllAccounts')?.addEventListener('click', () => {
        toggleAllCheckboxes('#accountCheckboxes', false);
    });
    
    // Files list
    document.getElementById('refreshFilesBtn')?.addEventListener('click', fetchFiles);
    
    // Permission modal
    document.getElementById('closeModalBtn')?.addEventListener('click', closeModal);
    document.getElementById('cancelModalBtn')?.addEventListener('click', closeModal);
    document.getElementById('savePermissionsBtn')?.addEventListener('click', savePermissions);
    document.getElementById('modalSelectAll')?.addEventListener('click', () => {
        toggleAllCheckboxes('#modalAccountCheckboxes', true);
    });
    document.getElementById('modalDeselectAll')?.addEventListener('click', () => {
        toggleAllCheckboxes('#modalAccountCheckboxes', false);
    });
    
    // Close modal on overlay click
    if (elements.permissionModal) {
        elements.permissionModal.addEventListener('click', (e) => {
            if (e.target === elements.permissionModal) {
                closeModal();
            }
        });
    }
    
    // Close modal on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && elements.permissionModal?.style.display === 'block') {
            closeModal();
        }
    });
}

// =============================================================================
// ENTRY POINT
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
    console.log("Admin page loaded, initializing...");
    cacheElements();
    attachEventListeners();
    checkAdminAccess();
});
