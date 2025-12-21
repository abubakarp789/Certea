// --- Navigation Logic ---
function switchView(viewId) {
    document.querySelectorAll('.view').forEach(el => el.classList.add('hidden'));

    const target = document.getElementById(`view-${viewId}`);
    if (target) {
        target.classList.remove('hidden');
    }

    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.getAttribute('onclick').includes(viewId)) {
            btn.classList.add('active');
        }
    });

    if (viewId === 'logs') loadLogs();
}

function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
    document.getElementById(`tab-${tabId}`).classList.remove('hidden');

    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.getAttribute('onclick').includes(tabId)) {
            btn.classList.add('active');
        }
    });
}

// --- UI Helpers ---
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');

    // Icon selection
    let icon = 'ℹ️';
    if (type === 'success') icon = '✅';
    if (type === 'error') icon = '❌';

    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;

    container.appendChild(toast);

    // Trigger animation
    requestAnimationFrame(() => {
        toast.classList.add('show');
    });

    // Remove after 3s
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function copyToClipboard(elementId) {
    const text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text);
    showToast('Copied to clipboard!', 'success');
}

function setupDragDrop(dropZoneId, inputId) {
    const dropZone = document.getElementById(dropZoneId);
    const input = document.getElementById(inputId);
    if (!dropZone || !input) return;

    const msg = dropZone.querySelector('.file-msg');

    dropZone.addEventListener('click', () => input.click());

    input.addEventListener('change', () => {
        if (input.files.length > 0) {
            msg.textContent = `Selected: ${input.files[0].name}`;
            dropZone.style.borderColor = 'var(--success)';
        }
    });

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) {
            input.files = e.dataTransfer.files;
            msg.textContent = `Selected: ${input.files[0].name}`;
            dropZone.style.borderColor = 'var(--success)';
        }
    });
}

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    // Setup file inputs
    const drops = [
        ['sign-text-drop', 'sign-text-key'],
        ['verify-text-drop', 'verify-text-key'],
        ['sign-file-key-drop', 'sign-file-key'],
        ['sign-file-doc-drop', 'sign-file-doc'],
        ['verify-file-key-drop', 'verify-file-key'],
        ['verify-file-doc-drop', 'verify-file-doc'],
        ['cert-sub-key-drop', 'cert-sub-key'],
        ['cert-ca-key-drop', 'cert-ca-key'],
        ['cert-file-drop', 'cert-file'],
        ['cert-verify-ca-drop', 'cert-verify-ca']
    ];
    drops.forEach(d => setupDragDrop(d[0], d[1]));

    // Connect Forms
    document.getElementById('generate-form').addEventListener('submit', handleGenerateKeys);
    document.getElementById('sign-text-form').addEventListener('submit', handleSignText);
    document.getElementById('verify-text-form').addEventListener('submit', handleVerifyText);
    document.getElementById('sign-file-form').addEventListener('submit', handleSignFile);
    document.getElementById('verify-file-form').addEventListener('submit', handleVerifyFile);
    document.getElementById('ca-create-form').addEventListener('submit', handleCreateCA);
    document.getElementById('ca-sign-form').addEventListener('submit', handleSignCert);
    document.getElementById('ca-verify-form').addEventListener('submit', handleVerifyCert);
});


// --- Key Generator ---
async function handleGenerateKeys(e) {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    const originalText = btn.textContent;
    btn.textContent = 'Generating safe primes...';
    btn.disabled = true;

    const passphrase = document.getElementById('gen-passphrase').value;
    const size = document.getElementById('gen-size').value;

    try {
        const response = await fetch('/api/keys/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                passphrase: passphrase || null,
                key_size: parseInt(size)
            })
        });

        const data = await response.json();
        if (response.ok) {
            document.getElementById('gen-result').classList.remove('hidden');
            window.generatedKeys = data;
            showToast('Keys generated successfully!', 'success');
        } else {
            showToast('Error: ' + data.detail, 'error');
        }
    } catch (err) {
        showToast('Network Error', 'error');
    } finally {
        btn.textContent = originalText;
        btn.disabled = false;
    }
}

function downloadKeys(isCA = false) {
    let source = window.generatedKeys;
    if (isCA) source = window.caKeys;

    if (!source) return;

    // Creating a simple zip-like download logic is hard in pure client JS without libs
    // Simplified: download individual files
    downloadFile(isCA ? 'ca_private_key.pem' : 'private_key.pem', source.private_key);
    setTimeout(() => {
        downloadFile(isCA ? 'ca_public_key.pem' : 'public_key.pem', source.public_key);
    }, 500);
}

function downloadFile(filename, content) {
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(content));
    element.setAttribute('download', filename);
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
}

// --- Text Operations ---
async function handleSignText(e) {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    btn.textContent = 'Signing...';

    const fileInput = document.getElementById('sign-text-key');
    const msg = document.getElementById('sign-text-msg').value;
    const pass = document.getElementById('sign-text-pass').value;

    if (!fileInput.files[0]) {
        showToast('Please select a private key file', 'error');
        btn.textContent = 'Sign Message';
        return;
    }

    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const response = await fetch('/api/sign/message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: msg,
                    private_key_pem: e.target.result,
                    passphrase: pass || null
                })
            });
            const data = await response.json();
            if (response.ok) {
                document.getElementById('sign-text-result').classList.remove('hidden');
                document.getElementById('sign-text-out').textContent = data.signature;
                showToast('Message Signed!', 'success');
            } else {
                showToast(data.detail, 'error');
            }
        } catch (err) { showToast('Error signing message', 'error'); }
        finally { btn.textContent = 'Sign Message'; }
    };
    reader.readAsText(fileInput.files[0]);
}

async function handleVerifyText(e) {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    btn.textContent = 'Verifying...';

    const fileInput = document.getElementById('verify-text-key');
    const msg = document.getElementById('verify-text-msg').value;
    const sig = document.getElementById('verify-text-sig').value;

    if (!fileInput.files[0]) { showToast('Missing Public Key', 'error'); btn.textContent = 'Verify'; return; }

    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const response = await fetch('/api/verify/message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: msg,
                    public_key_pem: e.target.result,
                    signature: sig
                })
            });
            const data = await response.json();
            if (response.ok) {
                const resBox = document.getElementById('verify-text-result');
                const status = document.getElementById('verify-text-status');
                const details = document.getElementById('verify-text-details');
                resBox.classList.remove('hidden');

                if (data.is_valid) {
                    status.textContent = "✅ VALID SIGNATURE";
                    status.className = "status-valid";
                    details.textContent = "Authentic.";
                    showToast('Valid Signature', 'success');
                } else {
                    status.textContent = "❌ INVALID SIGNATURE";
                    status.className = "status-invalid";
                    details.textContent = data.error_message || "Failed.";
                    showToast('Invalid Signature', 'error');
                }
            } else {
                showToast(data.detail, 'error');
            }
        } catch (err) { showToast('Error verifying', 'error'); }
        finally { btn.textContent = 'Verify Signature'; }
    };
    reader.readAsText(fileInput.files[0]);
}

// --- File Operations ---
async function handleSignFile(e) {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    btn.textContent = 'Uploading & Signing...';
    btn.disabled = true;

    const keyFile = document.getElementById('sign-file-key').files[0];
    const docFile = document.getElementById('sign-file-doc').files[0];
    const pass = document.getElementById('sign-file-pass').value;

    if (!keyFile || !docFile) {
        showToast('Please select both Key and File', 'error');
        btn.textContent = 'Sign File'; btn.disabled = false;
        return;
    }

    const formData = new FormData();
    formData.append('file', docFile);
    formData.append('private_key', keyFile);
    if (pass) formData.append('passphrase', pass);

    try {
        const response = await fetch('/api/sign/file', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();

        if (response.ok) {
            document.getElementById('sign-file-result').classList.remove('hidden');
            document.getElementById('sign-file-out').textContent = data.signature;
            document.getElementById('sign-file-digest').textContent = data.message_digest;
            showToast('File Signed Successfully', 'success');
        } else {
            showToast(data.detail, 'error');
        }
    } catch (err) {
        showToast('Network error', 'error');
    } finally {
        btn.textContent = 'Sign File';
        btn.disabled = false;
    }
}

async function handleVerifyFile(e) {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    btn.textContent = 'Checking Integrity...';
    btn.disabled = true;

    const keyFile = document.getElementById('verify-file-key').files[0];
    const docFile = document.getElementById('verify-file-doc').files[0];
    const sig = document.getElementById('verify-file-sig').value;

    if (!keyFile || !docFile || !sig) {
        showToast('Missing required fields', 'error');
        btn.textContent = 'Verify Integrity'; btn.disabled = false; return;
    }

    const formData = new FormData();
    formData.append('file', docFile);
    formData.append('public_key', keyFile);
    formData.append('signature', sig);

    try {
        const response = await fetch('/api/verify/file', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();

        if (response.ok) {
            const resBox = document.getElementById('verify-file-result');
            const status = document.getElementById('verify-file-status');
            const details = document.getElementById('verify-file-details');
            resBox.classList.remove('hidden');

            if (data.is_valid) {
                status.textContent = "✅ FILE IS AUTHENTIC";
                status.className = "status-valid";
                details.textContent = "Matches signature. File matches the original.";
                showToast('Verification Passed', 'success');
            } else {
                status.textContent = "❌ FILE CORRUPTED / INVALID";
                status.className = "status-invalid";
                details.textContent = "Signature does NOT match this file.";
                showToast('Verification Failed', 'error');
            }
        } else {
            showToast(data.detail, 'error');
        }
    } catch (err) {
        showToast('Network error', 'error');
    } finally {
        btn.textContent = 'Verify Integrity'; btn.disabled = false;
    }
}

// --- Certificate Authority ---
async function handleCreateCA(e) {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    btn.textContent = 'Initializing CA...'; btn.disabled = true;

    const name = document.getElementById('ca-name').value;
    const pass = document.getElementById('ca-pass').value;

    const formData = new FormData();
    formData.append('name', name);
    if (pass) formData.append('passphrase', pass);

    try {
        const response = await fetch('/api/ca/create', { method: 'POST', body: formData });
        const data = await response.json();
        if (response.ok) {
            window.caKeys = data;
            document.getElementById('ca-create-result').classList.remove('hidden');
            showToast('CA Initialized!', 'success');
        } else {
            showToast(data.detail, 'error');
        }
    } catch (err) { showToast('Network Error', 'error'); }
    finally { btn.textContent = 'Initialize CA'; btn.disabled = false; }
}

async function handleSignCert(e) {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    btn.textContent = 'Issuing...'; btn.disabled = true;

    const subject = document.getElementById('cert-subject').value;
    const subKey = document.getElementById('cert-sub-key').files[0];
    const caKey = document.getElementById('cert-ca-key').files[0];
    const pass = document.getElementById('cert-ca-pass').value;

    if (!subject || !subKey || !caKey) { showToast('Missing fields', 'error'); btn.disabled = false; btn.textContent = 'Issue'; return; }

    const formData = new FormData();
    formData.append('subject_name', subject);
    formData.append('subject_public_key', subKey);
    formData.append('ca_private_key', caKey);
    if (pass) formData.append('passphrase', pass);
    formData.append('days', 365);

    try {
        const response = await fetch('/api/ca/sign-certificate', { method: 'POST', body: formData });
        const data = await response.json();
        if (response.ok) {
            window.lastCert = data;
            document.getElementById('ca-sign-result').classList.remove('hidden');
            showToast('Certificate Issued', 'success');
        } else {
            showToast(data.detail, 'error');
        }
    } catch (err) { showToast('Network Error', 'error'); }
    finally { btn.textContent = 'Issue Certificate'; btn.disabled = false; }
}

function downloadCert() {
    if (!window.lastCert) return;
    // JSON export
    const content = JSON.stringify(window.lastCert, null, 2);
    downloadFile(`certificate_${window.lastCert.subject}.json`, content);
}

async function handleVerifyCert(e) {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    btn.textContent = 'Verifying...'; btn.disabled = true;

    const certFile = document.getElementById('cert-file').files[0];
    const caFile = document.getElementById('cert-verify-ca').files[0];

    if (!certFile || !caFile) { showToast('Missing files', 'error'); btn.disabled = false; btn.textContent = 'Verify'; return; }

    const formData = new FormData();
    formData.append('certificate_file', certFile);
    formData.append('ca_public_key', caFile);

    try {
        const response = await fetch('/api/ca/verify-certificate', { method: 'POST', body: formData });
        const data = await response.json();

        const resBox = document.getElementById('ca-verify-result');
        const status = document.getElementById('cert-status');
        const details = document.getElementById('cert-details');
        resBox.classList.remove('hidden');

        if (data.is_valid) {
            status.textContent = "✅ TRUSTED";
            status.className = "status-valid";
            details.textContent = `Issued by: ${data.issuer}`;
            showToast('Certificate Trusted', 'success');
        } else {
            status.textContent = "❌ UNTRUSTED / INVALID";
            status.className = "status-invalid";
            details.textContent = data.error || "Signature mismatch";
            showToast('Certificate Invalid', 'error');
        }
    } catch (err) { showToast('Network Error', 'error'); }
    finally { btn.textContent = 'Verify Validity'; btn.disabled = false; }
}


// --- Logs ---
async function loadLogs() {
    const tbody = document.getElementById('logs-body');
    tbody.innerHTML = '<tr><td colspan="4"><div class="loader"></div> Loading...</td></tr>';

    try {
        const response = await fetch('/api/logs');
        const logs = await response.json();

        tbody.innerHTML = '';
        if (logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-secondary)">No logs found</td></tr>';
            return;
        }

        logs.reverse().forEach(log => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${new Date(log.timestamp).toLocaleString()}</td>
                <td class="${log.result ? 'status-valid' : 'status-invalid'}">${log.result ? 'Valid' : 'Invalid'}</td>
                <td style="font-family: monospace; color: var(--accent);">${log.message_id}</td>
                <td style="font-family: monospace; color: var(--text-secondary);">${log.signature_id}</td>
            `;
            tbody.appendChild(row);
        });
    } catch (err) {
        tbody.innerHTML = '<tr><td colspan="4">Failed to load logs</td></tr>';
    }
}
