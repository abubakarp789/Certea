/**
 * Utility Functions for Digital Signature Validator
 * 
 * Common helper functions for:
 * - Clipboard operations
 * - File handling
 * - Keyboard shortcuts
 * - Local storage persistence
 * - Toast notifications
 */

// --- Constants ---
const STORAGE_KEYS = {
    DARK_MODE: 'cybersign_dark_mode',
    LAST_KEY_SIZE: 'cybersign_last_key_size',
    RECENT_OPS: 'cybersign_recent_operations',
    SETTINGS: 'cybersign_settings'
};

const KEYBOARD_SHORTCUTS = {
    'Ctrl+G': { action: 'generate', view: 'generate' },
    'Ctrl+S': { action: 'sign', view: 'sign-text' },
    'Ctrl+V': { action: 'verify', view: 'verify-text' },
    'Ctrl+D': { action: 'toggleDarkMode' },
    'Escape': { action: 'closeModal' }
};

// --- Clipboard Operations ---
async function copyToClipboardEnhanced(text, showFeedback = true) {
    try {
        await navigator.clipboard.writeText(text);
        if (showFeedback) {
            showToast('Copied to clipboard!', 'success');
        }
        return true;
    } catch (err) {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-9999px';
        document.body.appendChild(textArea);
        textArea.select();
        
        try {
            document.execCommand('copy');
            if (showFeedback) {
                showToast('Copied to clipboard!', 'success');
            }
            return true;
        } catch (fallbackErr) {
            showToast('Failed to copy to clipboard', 'error');
            return false;
        } finally {
            document.body.removeChild(textArea);
        }
    }
}

function copyElementContent(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        return copyToClipboardEnhanced(element.textContent || element.value);
    }
    return false;
}

// --- File Handling ---
function readFileAsText(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(e.target.result);
        reader.onerror = (e) => reject(new Error('Failed to read file'));
        reader.readAsText(file);
    });
}

function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(e.target.result);
        reader.onerror = (e) => reject(new Error('Failed to read file'));
        reader.readAsArrayBuffer(file);
    });
}

function downloadFile(filename, content, mimeType = 'text/plain') {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    URL.revokeObjectURL(url);
}

function downloadJSON(filename, data) {
    const content = JSON.stringify(data, null, 2);
    downloadFile(filename, content, 'application/json');
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// --- Keyboard Shortcuts ---
function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Build shortcut string
        let shortcut = '';
        if (e.ctrlKey || e.metaKey) shortcut += 'Ctrl+';
        if (e.altKey) shortcut += 'Alt+';
        if (e.shiftKey) shortcut += 'Shift+';
        shortcut += e.key.toUpperCase();
        
        const handler = KEYBOARD_SHORTCUTS[shortcut];
        if (handler) {
            e.preventDefault();
            
            if (handler.action === 'toggleDarkMode') {
                toggleDarkMode();
            } else if (handler.action === 'closeModal') {
                closeAllModals();
            } else if (handler.view) {
                switchView(handler.view);
            }
        }
    });
}

function showShortcutsHelp() {
    const shortcuts = Object.entries(KEYBOARD_SHORTCUTS)
        .map(([key, value]) => `${key}: ${value.action}`)
        .join('\n');
    
    showToast('Keyboard shortcuts:\n' + shortcuts, 'info');
}

// --- Dark Mode ---
function initDarkMode() {
    // Check saved preference
    const savedMode = localStorage.getItem(STORAGE_KEYS.DARK_MODE);
    
    // Check system preference if no saved preference
    if (savedMode === null) {
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (!prefersDark) {
            document.body.classList.add('light-mode');
        }
    } else if (savedMode === 'light') {
        document.body.classList.add('light-mode');
    }
    
    // Listen for system preference changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (localStorage.getItem(STORAGE_KEYS.DARK_MODE) === null) {
            document.body.classList.toggle('light-mode', !e.matches);
        }
    });
}

function toggleDarkMode() {
    document.body.classList.toggle('light-mode');
    const isLight = document.body.classList.contains('light-mode');
    localStorage.setItem(STORAGE_KEYS.DARK_MODE, isLight ? 'light' : 'dark');
    
    // Update toggle button if exists
    const toggle = document.getElementById('dark-mode-toggle');
    if (toggle) {
        toggle.textContent = isLight ? '🌙' : '☀️';
    }
    
    showToast(`${isLight ? 'Light' : 'Dark'} mode enabled`, 'success');
}

function isDarkMode() {
    return !document.body.classList.contains('light-mode');
}

// --- Local Storage ---
function saveToStorage(key, value) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
        return true;
    } catch (e) {
        console.error('Failed to save to storage:', e);
        return false;
    }
}

function loadFromStorage(key, defaultValue = null) {
    try {
        const value = localStorage.getItem(key);
        return value ? JSON.parse(value) : defaultValue;
    } catch (e) {
        console.error('Failed to load from storage:', e);
        return defaultValue;
    }
}

function removeFromStorage(key) {
    localStorage.removeItem(key);
}

// Settings management
function saveSettings(settings) {
    return saveToStorage(STORAGE_KEYS.SETTINGS, settings);
}

function loadSettings() {
    return loadFromStorage(STORAGE_KEYS.SETTINGS, {
        defaultKeySize: 2048,
        defaultPadding: 'PSS',
        autoSaveKeys: false
    });
}

// Recent operations history
function addRecentOperation(operation) {
    const recent = loadFromStorage(STORAGE_KEYS.RECENT_OPS, []);
    recent.unshift({
        ...operation,
        timestamp: new Date().toISOString()
    });
    
    // Keep only last 50 operations
    if (recent.length > 50) {
        recent.pop();
    }
    
    saveToStorage(STORAGE_KEYS.RECENT_OPS, recent);
}

function getRecentOperations(limit = 10) {
    const recent = loadFromStorage(STORAGE_KEYS.RECENT_OPS, []);
    return recent.slice(0, limit);
}

// --- Progress Indicators ---
function showProgress(containerId, determinate = false, value = 0) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    let progressBar = container.querySelector('.progress-bar');
    if (!progressBar) {
        progressBar = document.createElement('div');
        progressBar.className = 'progress-bar';
        progressBar.innerHTML = '<div class="progress-fill"></div>';
        container.appendChild(progressBar);
    }
    
    const fill = progressBar.querySelector('.progress-fill');
    if (determinate) {
        fill.style.width = `${value}%`;
        fill.classList.remove('indeterminate');
    } else {
        fill.classList.add('indeterminate');
    }
    
    progressBar.classList.remove('hidden');
}

function hideProgress(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    const progressBar = container.querySelector('.progress-bar');
    if (progressBar) {
        progressBar.classList.add('hidden');
    }
}

function updateProgress(containerId, value) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    const fill = container.querySelector('.progress-fill');
    if (fill) {
        fill.style.width = `${value}%`;
    }
}

// --- Loading States ---
function setLoading(button, loading = true, loadingText = 'Processing...') {
    if (loading) {
        button.dataset.originalText = button.textContent;
        button.textContent = loadingText;
        button.disabled = true;
        button.classList.add('loading');
    } else {
        button.textContent = button.dataset.originalText || button.textContent;
        button.disabled = false;
        button.classList.remove('loading');
    }
}

// --- Modal Handling ---
function closeAllModals() {
    document.querySelectorAll('.modal.active').forEach(modal => {
        modal.classList.remove('active');
    });
}

function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
    }
}

// --- Form Validation ---
function validateRequired(formId) {
    const form = document.getElementById(formId);
    if (!form) return false;
    
    const requiredFields = form.querySelectorAll('[required]');
    let valid = true;
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            field.classList.add('error');
            valid = false;
        } else {
            field.classList.remove('error');
        }
    });
    
    return valid;
}

function clearFormErrors(formId) {
    const form = document.getElementById(formId);
    if (form) {
        form.querySelectorAll('.error').forEach(el => el.classList.remove('error'));
    }
}

// --- Debounce and Throttle ---
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function throttle(func, limit) {
    let inThrottle;
    return function executedFunction(...args) {
        if (!inThrottle) {
            func(...args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// --- Date Formatting ---
function formatDate(date) {
    return new Date(date).toLocaleString();
}

function formatRelativeTime(date) {
    const now = new Date();
    const diff = now - new Date(date);
    
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days} day${days > 1 ? 's' : ''} ago`;
    if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    return 'Just now';
}

// --- Hex/Base64 Conversion ---
function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
}

function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function base64ToHex(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytesToHex(bytes);
}

function hexToBase64(hex) {
    const bytes = hexToBytes(hex);
    const binary = String.fromCharCode.apply(null, bytes);
    return btoa(binary);
}

// --- Export utilities ---
window.CyberSignUtils = {
    // Clipboard
    copyToClipboard: copyToClipboardEnhanced,
    copyElementContent,
    
    // Files
    readFileAsText,
    readFileAsArrayBuffer,
    downloadFile,
    downloadJSON,
    formatFileSize,
    
    // Keyboard
    initKeyboardShortcuts,
    showShortcutsHelp,
    
    // Dark mode
    initDarkMode,
    toggleDarkMode,
    isDarkMode,
    
    // Storage
    saveToStorage,
    loadFromStorage,
    removeFromStorage,
    saveSettings,
    loadSettings,
    addRecentOperation,
    getRecentOperations,
    
    // Progress
    showProgress,
    hideProgress,
    updateProgress,
    setLoading,
    
    // Modals
    showModal,
    closeAllModals,
    
    // Forms
    validateRequired,
    clearFormErrors,
    
    // Utilities
    debounce,
    throttle,
    formatDate,
    formatRelativeTime,
    
    // Conversion
    hexToBytes,
    bytesToHex,
    base64ToHex,
    hexToBase64,
    
    // Constants
    STORAGE_KEYS
};
