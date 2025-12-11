/**
 * User Files JavaScript Module
 * Handles secure file downloads with integrity verification
 */

import { 
    getCsrfToken, 
    formatBytes, 
    truncateHash, 
    escapeHtml, 
    secureFetch, 
    verifyAuth 
} from './utils.js';

// --- DOM Elements (cached on init) ---
let elements = {};

// =============================================================================
// FILE LIST
// =============================================================================

/**
 * Fetches and displays user's accessible files
 */
async function loadFiles() {
    try {
        const response = await secureFetch('/api/files');
        
        if (!response.ok) {
            if (response.status === 403 || response.status === 401) {
                window.location.href = '/login.html';
                return;
            }
            throw new Error(`Failed to load files: ${response.status}`);
        }
        
        const files = await response.json();
        renderFiles(files);
    } catch (error) {
        console.error("Error loading files:", error);
        elements.loading.innerHTML = `
            <span style="color: #dc3545;">Error loading files. Please try again.</span>
        `;
    }
}

/**
 * Renders the file list table
 * @param {Array} files - Array of file objects
 */
function renderFiles(files) {
    elements.loading.style.display = 'none';
    
    if (files.length === 0) {
        elements.noFiles.style.display = 'block';
        elements.filesContainer.style.display = 'none';
        return;
    }
    
    elements.noFiles.style.display = 'none';
    elements.filesContainer.style.display = 'block';
    
    const tbody = elements.filesTbody;
    tbody.innerHTML = '';
    
    files.forEach(file => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${escapeHtml(file.filename)}</strong></td>
            <td>${escapeHtml(file.file_type)}</td>
            <td>${formatBytes(file.file_size)}</td>
            <td>${new Date(file.uploaded_at).toLocaleDateString()}</td>
            <td>
                <button class="btn-green btn-sm download-btn" 
                        data-file-id="${escapeHtml(file.id)}"
                        data-filename="${escapeHtml(file.filename)}"
                        data-hash="${escapeHtml(file.blake3_hash)}">
                    Verify & Download
                </button>
            </td>
        `;
        
        // Attach download handler
        const downloadBtn = tr.querySelector('.download-btn');
        downloadBtn.addEventListener('click', handleDownloadClick);
        
        tbody.appendChild(tr);
    });
}

// =============================================================================
// SECURE DOWNLOAD LOGIC
// =============================================================================

/**
 * Handles download button click
 * @param {Event} e - Click event
 */
async function handleDownloadClick(e) {
    const btn = e.currentTarget;
    const fileId = btn.dataset.fileId;
    const filename = btn.dataset.filename;
    const expectedHash = btn.dataset.hash;
    
    await downloadSecurely(fileId, filename, expectedHash, btn);
}

/**
 * Performs secure download with integrity verification
 * @param {string} fileId - File ID
 * @param {string} filename - Original filename
 * @param {string} expectedHash - Expected BLAKE3 hash
 * @param {HTMLElement} btn - Button element for UI feedback
 */
async function downloadSecurely(fileId, filename, expectedHash, btn) {
    const originalText = btn.innerHTML;
    
    // UI Feedback: Loading
    btn.disabled = true;
    btn.innerHTML = 'Verifying...';
    btn.classList.add('btn-loading');
    
    try {
        const csrfToken = await getCsrfToken();
        if (!csrfToken) {
            window.location.href = '/login.html';
            return;
        }
        
        // Fetch the file stream
        const response = await fetch(`/api/files/${fileId}/download`, {
            headers: { 'X-CSRF-Token': csrfToken }
        });
        
        // Security Check: HTTP Status
        if (!response.ok) {
            const errorText = await response.text();
            const isContaminated = errorText.toLowerCase().includes('contaminated') || 
                                   errorText.toLowerCase().includes('integrity');
            throw new Error(isContaminated ? 'INTEGRITY_FAIL' : 'SERVER_ERROR');
        }
        
        // Security Check: Verify Headers
        const serverHash = response.headers.get('X-Blake3-Hash');
        const integrityStatus = response.headers.get('X-File-Integrity');
        
        // Critical: Both header checks must pass
        if (integrityStatus !== 'verified') {
            throw new Error('INTEGRITY_FAIL');
        }
        
        if (serverHash && expectedHash && serverHash !== expectedHash) {
            throw new Error('HASH_MISMATCH');
        }
        
        // Download successful - get blob and trigger save
        const blob = await response.blob();
        
        // Create download link
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
        
        // Show success modal
        showVerificationModal(true, serverHash || expectedHash);
        
    } catch (error) {
        console.error('Download error:', error);
        
        const isSecurityError = ['INTEGRITY_FAIL', 'HASH_MISMATCH'].includes(error.message);
        showVerificationModal(false, expectedHash, isSecurityError);
        
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
        btn.classList.remove('btn-loading');
    }
}

// =============================================================================
// VERIFICATION MODAL
// =============================================================================

/**
 * Shows the integrity verification modal
 * @param {boolean} success - Whether verification was successful
 * @param {string} hash - The cryptographic hash
 * @param {boolean} isSecurityRisk - Whether this is a security concern
 */
function showVerificationModal(success, hash, isSecurityRisk = false) {
    const modal = elements.verificationModal;
    const icon = elements.verifyIcon;
    const title = elements.verifyTitle;
    const msg = elements.verifyMsg;
    const hashEl = elements.verifyHash;
    const content = elements.modalContent;
    
    // Reset classes
    content.classList.remove('modal-success', 'modal-error');
    
    if (success) {
        // SUCCESS STATE: Green Modal
        content.classList.add('modal-success');
        icon.innerHTML = '<span class="icon-success">&#10003;</span>';
        title.textContent = 'Integrity Verified';
        title.style.color = '#28a745';
        msg.innerHTML = `
            <strong>No contamination detected.</strong><br>
            The file on the server matches the cryptographic signature exactly.
            Your download is secure and has not been tampered with.
        `;
    } else {
        // FAILURE STATE: Red Modal
        content.classList.add('modal-error');
        icon.innerHTML = '<span class="icon-error">&#10007;</span>';
        
        if (isSecurityRisk) {
            title.textContent = 'Security Alert';
            title.style.color = '#dc3545';
            msg.innerHTML = `
                <strong>CRITICAL: File integrity check failed!</strong><br>
                The file may have been tampered with or corrupted.
                <strong>The download was blocked for your safety.</strong><br><br>
                Please contact your administrator immediately.
            `;
        } else {
            title.textContent = 'Download Failed';
            title.style.color = '#dc3545';
            msg.innerHTML = `
                An error occurred during the download process.<br>
                Please try again or contact support if the issue persists.
            `;
        }
    }
    
    // Set hash display
    hashEl.textContent = hash || 'Unknown';
    
    // Show modal
    modal.style.display = 'block';
}

/**
 * Closes the verification modal
 */
function closeModal() {
    elements.verificationModal.style.display = 'none';
}

// =============================================================================
// INITIALIZATION
// =============================================================================

/**
 * Caches DOM element references
 */
function cacheElements() {
    elements = {
        loading: document.getElementById('loading'),
        noFiles: document.getElementById('no-files'),
        filesContainer: document.getElementById('files-container'),
        filesTbody: document.getElementById('files-tbody'),
        
        // Modal
        verificationModal: document.getElementById('verificationModal'),
        modalContent: document.querySelector('#verificationModal .modal-content'),
        verifyIcon: document.getElementById('verifyIcon'),
        verifyTitle: document.getElementById('verifyTitle'),
        verifyMsg: document.getElementById('verifyMsg'),
        verifyHash: document.getElementById('verifyHash')
    };
}

/**
 * Attaches event listeners
 */
function attachEventListeners() {
    // Close modal button
    document.getElementById('closeModalBtn')?.addEventListener('click', closeModal);
    
    // Close on overlay click
    elements.verificationModal?.addEventListener('click', (e) => {
        if (e.target === elements.verificationModal) {
            closeModal();
        }
    });
    
    // Close on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && elements.verificationModal?.style.display === 'block') {
            closeModal();
        }
    });
    
    // Back to dashboard link
    document.querySelector('a[href="/"]')?.addEventListener('click', (e) => {
        // Allow default navigation
    });
}

// =============================================================================
// ENTRY POINT
// =============================================================================

document.addEventListener('DOMContentLoaded', async () => {
    cacheElements();
    attachEventListeners();
    
    // Verify authentication before loading
    const isAuth = await verifyAuth();
    if (isAuth) {
        loadFiles();
    }
});
