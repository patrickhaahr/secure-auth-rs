/**
 * Shared utility functions for SecureAuth frontend
 * @module utils
 */

/**
 * Fetches a CSRF token from the server
 * @returns {Promise<string|null>} The CSRF token or null if failed
 */
export async function getCsrfToken() {
    try {
        const response = await fetch("/api/csrf-token");
        if (!response.ok) return null;
        const data = await response.json();
        return data.csrf_token;
    } catch (error) {
        console.error("Error fetching CSRF token:", error);
        return null;
    }
}

/**
 * Verifies user authentication by checking the CSRF endpoint
 * Redirects to login if not authenticated
 * @returns {Promise<boolean>} True if authenticated, false otherwise (redirects)
 */
export async function verifyAuth() {
    try {
        const response = await fetch("/api/csrf-token");
        if (!response.ok) {
            window.location.href = "/login.html";
            return false;
        }
        return true;
    } catch (error) {
        console.error("Auth verification failed:", error);
        window.location.href = "/login.html";
        return false;
    }
}

/**
 * Formats bytes into human-readable string
 * @param {number} bytes - The number of bytes
 * @returns {string} Formatted string (e.g., "1.5 MB")
 */
export function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Truncates a hash for display purposes
 * @param {string} hash - The full hash string
 * @param {number} [chars=8] - Number of characters to show on each end
 * @returns {string} Truncated hash (e.g., "abc12345...xyz98765")
 */
export function truncateHash(hash, chars = 8) {
    if (!hash || hash.length <= chars * 2 + 3) return hash || '';
    return hash.substring(0, chars) + '...' + hash.substring(hash.length - chars);
}

/**
 * Escapes HTML special characters to prevent XSS
 * @param {string} text - The text to escape
 * @returns {string} Escaped text safe for HTML insertion
 */
export function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Shows a toast/notification message
 * @param {string} message - Message to display
 * @param {string} [type='info'] - Type: 'success', 'error', 'info', 'warning'
 * @param {number} [duration=5000] - Duration in ms
 */
export function showToast(message, type = 'info', duration = 5000) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 6px;
        color: white;
        font-weight: 500;
        z-index: 9999;
        animation: slideIn 0.3s ease;
        background-color: ${type === 'success' ? '#28a745' : type === 'error' ? '#dc3545' : type === 'warning' ? '#ffc107' : '#007bff'};
    `;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

/**
 * Performs a fetch with automatic CSRF token handling
 * @param {string} url - The URL to fetch
 * @param {object} [options={}] - Fetch options
 * @returns {Promise<Response>} The fetch response
 */
export async function secureFetch(url, options = {}) {
    const csrfToken = await getCsrfToken();
    if (!csrfToken) {
        window.location.href = "/login.html";
        throw new Error("Authentication required");
    }

    const headers = {
        ...options.headers,
        "X-CSRF-Token": csrfToken
    };

    const response = await fetch(url, { ...options, headers });
    
    // Only redirect on 401 (Unauthorized) - not on 403 (Forbidden)
    // 403 may mean "not authorized for this resource" which is different from "not authenticated"
    if (response.status === 401) {
        window.location.href = "/login.html";
        throw new Error("Authentication required");
    }
    
    return response;
}

/**
 * Performs logout by calling the logout API and redirecting
 */
export async function logout() {
    try {
        const csrfToken = await getCsrfToken();
        await fetch("/api/logout", { 
            method: "POST",
            headers: csrfToken ? { "X-CSRF-Token": csrfToken } : {}
        });
    } catch (error) {
        console.error("Logout error:", error);
    }
    window.location.href = "/login.html";
}
