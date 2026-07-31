// Get CSRF token from meta tag
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]').content;
}

// Show toast notifications
function showToast(message, type = 'success') {
    const container = document.getElementById('toastContainer');
    const toastId = 'toast-' + Date.now();
    const bgClass = type === 'success' ? 'bg-success' : type === 'error' ? 'bg-danger' : 'bg-warning';
    const iconClass = type === 'success' ? 'fa-circle-check' : type === 'error' ? 'fa-circle-xmark' : 'fa-triangle-exclamation';
    
    const toastHtml = `
        <div id="${toastId}" class="toast ${bgClass} text-white border-0" role="alert" aria-live="assertive" aria-atomic="true" data-bs-autohide="true" data-bs-delay="8000">
            <div class="toast-header ${bgClass} text-white border-0 d-flex justify-content-between align-items-center">
                <div class="d-flex align-items-center">
                    <i class="fas ${iconClass} me-2"></i>
                    <strong class="me-auto">${type.charAt(0).toUpperCase() + type.slice(1)}</strong>
                </div>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">${message}</div>
        </div>
    `;
    container.insertAdjacentHTML('beforeend', toastHtml);
    
    const toastEl = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastEl);
    toast.show();
    
    setTimeout(() => {
        if (toastEl && toastEl.parentNode) {
            toastEl.parentNode.removeChild(toastEl);
        }
    }, 9000);
}

// Copy to clipboard
function copyToClipboard(elementId) {
    const el = document.getElementById(elementId);
    if (el) {
        navigator.clipboard.writeText(el.value || el.textContent).then(() => {
            showToast('Copied to clipboard!', 'success');
        }).catch(() => {
            showToast('Failed to copy', 'error');
        });
    }
}

// Clear fields
function clearFields(fieldIds) {
    fieldIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
}

// Generate AES key
async function generateAESKey() {
    try {
        const response = await fetch('/api/keys/generate-aes');
        const data = await response.json();
        if (data.success) {
            document.getElementById('aesKey').value = data.key;
            showToast('AES key generated', 'success');
        }
    } catch (e) {
        showToast('Failed to generate key', 'error');
    }
}

// Generate DES key
async function generateDESKey() {
    try {
        const response = await fetch('/api/keys/generate-des');
        const data = await response.json();
        if (data.success) {
            document.getElementById('desKey').value = data.key;
            showToast('DES key generated', 'success');
        }
    } catch (e) {
        showToast('Failed to generate key', 'error');
    }
}

// Generate RSA key pair
async function generateRSAKeys() {
    try {
        const response = await fetch('/api/keys/generate-rsa');
        const data = await response.json();
        if (data.success) {
            document.getElementById('rsaPublicKey').value = data.public_key;
            const rsaPrivateKeyEl = document.getElementById('rsaPrivateKey');
            if (rsaPrivateKeyEl) {
                rsaPrivateKeyEl.value = data.private_key;
            }
            showToast('RSA key pair generated! SAVE the private key!', 'success');
        }
    } catch (e) {
        showToast('Failed to generate keys', 'error');
    }
}

// Encrypt AES
async function encryptAES() {
    try {
        const plaintext = document.getElementById('aesPlaintext').value;
        const key = document.getElementById('aesKey').value;
        const response = await fetch('/api/encrypt/aes', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ plaintext, key })
        });
        const data = await response.json();
        if (data.success) {
            document.getElementById('aesCiphertext').value = data.ciphertext;
            showToast('Text encrypted successfully!', 'success');
        } else {
            showToast(data.error, 'error');
        }
    } catch (e) {
        showToast('Encryption failed', 'error');
    }
}

// Decrypt AES
async function decryptAES() {
    try {
        const ciphertext = document.getElementById('aesDecryptCiphertext').value;
        const key = document.getElementById('aesDecryptKey').value;
        const response = await fetch('/api/decrypt/aes', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ ciphertext, key })
        });
        const data = await response.json();
        if (data.success) {
            document.getElementById('aesDecryptPlaintext').value = data.plaintext;
            showToast('Text decrypted successfully!', 'success');
        } else {
            showToast(data.error, 'error');
        }
    } catch (e) {
        showToast('Decryption failed', 'error');
    }
}

// Encrypt DES
async function encryptDES() {
    try {
        const plaintext = document.getElementById('desPlaintext').value;
        const key = document.getElementById('desKey').value;
        const response = await fetch('/api/encrypt/des', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ plaintext, key })
        });
        const data = await response.json();
        if (data.success) {
            document.getElementById('desCiphertext').value = data.ciphertext;
            showToast('Text encrypted!', 'success');
        } else {
            showToast(data.error, 'error');
        }
    } catch (e) {
        showToast('Encryption failed', 'error');
    }
}

// Decrypt DES
async function decryptDES() {
    try {
        const ciphertext = document.getElementById('desDecryptCiphertext').value;
        const key = document.getElementById('desDecryptKey').value;
        const response = await fetch('/api/decrypt/des', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ ciphertext, key })
        });
        const data = await response.json();
        if (data.success) {
            document.getElementById('desDecryptPlaintext').value = data.plaintext;
            showToast('Text decrypted!', 'success');
        } else {
            showToast(data.error, 'error');
        }
    } catch (e) {
        showToast('Decryption failed', 'error');
    }
}

// Encrypt RSA
async function encryptRSA() {
    try {
        const plaintext = document.getElementById('rsaPlaintext').value;
        const public_key = document.getElementById('rsaPublicKey').value;
        const response = await fetch('/api/encrypt/rsa', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ plaintext, public_key })
        });
        const data = await response.json();
        if (data.success) {
            document.getElementById('rsaCiphertext').value = data.ciphertext;
            showToast('Text encrypted!', 'success');
        } else {
            showToast(data.error, 'error');
        }
    } catch (e) {
        showToast('Encryption failed', 'error');
    }
}

// Decrypt RSA
async function decryptRSA() {
    try {
        const ciphertext = document.getElementById('rsaDecryptCiphertext').value;
        const private_key = document.getElementById('rsaDecryptPrivateKey').value;
        const response = await fetch('/api/decrypt/rsa', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ ciphertext, private_key })
        });
        const data = await response.json();
        if (data.success) {
            document.getElementById('rsaDecryptPlaintext').value = data.plaintext;
            showToast('Text decrypted!', 'success');
        } else {
            showToast(data.error, 'error');
        }
    } catch (e) {
        showToast('Decryption failed', 'error');
    }
}

// Generate password
async function generatePassword() {
    try {
        const response = await fetch('/api/password/generate');
        const data = await response.json();
        if (data.success) {
            document.getElementById('passwordOutput').value = data.password;
            document.getElementById('strengthInput').value = data.password;
            checkPasswordStrength();
        }
    } catch (e) {
        showToast('Failed to generate password', 'error');
    }
}

// Check password strength
async function checkPasswordStrength() {
    const password = document.getElementById('strengthInput').value;
    try {
        const response = await fetch('/api/password/strength', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ password })
        });
        const data = await response.json();
        if (data.success) {
            const bar = document.getElementById('strengthBar');
            const text = document.getElementById('strengthText');
            bar.style.width = data.score + '%';
            text.textContent = 'Strength: ' + data.level;
            if (data.score < 30) {
                bar.className = 'progress-bar bg-danger';
            } else if (data.score < 50) {
                bar.className = 'progress-bar bg-warning';
            } else if (data.score < 70) {
                bar.className = 'progress-bar bg-info';
            } else if (data.score < 90) {
                bar.className = 'progress-bar bg-primary';
            } else {
                bar.className = 'progress-bar bg-success';
            }
        }
    } catch (e) {
        console.error(e);
    }
}

// Hash generator
function updateHashButtonActive(algorithm) {
    const btnSha256 = document.getElementById('hashBtnSha256');
    const btnSha512 = document.getElementById('hashBtnSha512');
    const btnMd5 = document.getElementById('hashBtnMd5');

    const buttons = [
        { btn: btnSha256, algo: 'sha256', success: true },
        { btn: btnSha512, algo: 'sha512', success: true },
        { btn: btnMd5, algo: 'md5', success: false }
    ];

    buttons.forEach(item => {
        if (!item.btn) return;
        item.btn.classList.remove('btn-success', 'btn-warning', 'active');
        if (item.success) {
            item.btn.classList.remove('btn-outline-success');
            item.btn.classList.add('btn-outline-success');
        } else {
            item.btn.classList.remove('btn-outline-warning');
            item.btn.classList.add('btn-outline-warning');
        }
    });

    const activeMap = { sha256: btnSha256, sha512: btnSha512, md5: btnMd5 };
    const activeBtn = activeMap[algorithm];
    if (activeBtn) {
        activeBtn.classList.add('active');
        if (algorithm === 'md5') {
            activeBtn.classList.remove('btn-outline-warning');
            activeBtn.classList.add('btn-warning');
        } else {
            activeBtn.classList.remove('btn-outline-success');
            activeBtn.classList.add('btn-success');
        }
    }
}

function copyTextById(elementId) {
    const el = document.getElementById(elementId);
    if (!el) {
        showToast('Nothing to copy yet', 'warning');
        return;
    }
    const value = (el.value !== undefined && el.value !== null && el.value !== '') ? el.value : el.textContent;
    if (value && value !== '—') {
        navigator.clipboard.writeText(value).then(() => {
            showToast('Copied to clipboard!', 'success');
        }).catch(() => {
            showToast('Failed to copy', 'error');
        });
    } else {
        showToast('Nothing to copy yet', 'warning');
    }
}

function setCompareHash(algorithm, hashValue) {
    const cellId = 'compare' + algorithm.charAt(0).toUpperCase() + algorithm.slice(1);
    const cell = document.getElementById(cellId);
    if (cell) {
        cell.textContent = hashValue;
    }
}

async function generateHash(algorithm) {
    const text = document.getElementById('hashInput').value;
    if (!text) {
        showToast('Please enter text to hash', 'error');
        return;
    }
    try {
        updateHashButtonActive(algorithm);
        const response = await fetch('/api/hash/' + algorithm, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ text })
        });
        const data = await response.json();
        if (data.success) {
            document.getElementById('hashOutput').value = data.hash;
            setCompareHash(algorithm, data.hash);
            showToast(algorithm.toUpperCase() + ' hash generated!', 'success');
        } else {
            showToast(data.error, 'error');
        }
    } catch (e) {
        showToast('Failed to generate hash', 'error');
    }
}

async function generateAllHashes() {
    const text = document.getElementById('hashInput').value;
    if (!text) {
        showToast('Please enter text to hash', 'error');
        return;
    }
    const algorithms = ['sha256', 'sha512', 'md5'];
    let allSuccess = true;
    updateHashButtonActive('sha256');

    for (const algo of algorithms) {
        try {
            const response = await fetch('/api/hash/' + algo, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify({ text })
            });
            const data = await response.json();
            if (data.success) {
                setCompareHash(algo, data.hash);
                if (algo === 'sha256') {
                    document.getElementById('hashOutput').value = data.hash;
                }
            } else {
                allSuccess = false;
            }
        } catch (e) {
            allSuccess = false;
        }
    }

    if (allSuccess) {
        showToast('All hashes generated! Comparison updated.', 'success');
    } else {
        showToast('Some hashes failed to generate', 'error');
    }
}

// Performance test
let performanceChart = null;

function setPerfLoading(isLoading) {
    const btn = document.getElementById('perfRunBtn');
    const icon = document.getElementById('perfRunIcon');
    const label = document.getElementById('perfRunLabel');
    if (!btn) return;
    btn.disabled = isLoading;
    if (isLoading) {
        if (icon) {
            icon.classList.remove('fa-chart-line');
            icon.classList.add('fa-sync-alt', 'fa-spin');
        }
        if (label) label.textContent = 'Running Benchmark...';
    } else {
        if (icon) {
            icon.classList.remove('fa-sync-alt', 'fa-spin');
            icon.classList.add('fa-chart-line');
        }
        if (label) label.textContent = 'Re-run Benchmark';
    }
}

function hidePerfEmptyState() {
    const empty = document.getElementById('perfEmptyState');
    if (empty) empty.style.display = 'none';
    const resultsTable = document.getElementById('perfResultsTable');
    if (resultsTable) resultsTable.classList.remove('d-none');
}

function renderPerfResultsTable(results) {
    const tbody = document.getElementById('perfResultsBody');
    if (!tbody || !results) return;
    tbody.innerHTML = '';
    const badgeBySecurity = {
        'Very High': 'bg-info',
        'High': 'bg-success',
        'Medium': 'bg-secondary',
        'Very Low': 'bg-warning text-dark'
    };
    const badgeBySpeed = {
        'Fast': 'bg-success',
        'Medium': 'bg-warning text-dark',
        'Slow': 'bg-danger'
    };
    Object.keys(results).forEach(algo => {
        const r = results[algo];
        const secBadge = badgeBySecurity[r.security_level] || 'bg-secondary';
        const speedBadge = badgeBySpeed[r.speed] || 'bg-secondary';
        tbody.insertAdjacentHTML('beforeend', `
            <tr class="border-secondary-subtle">
                <td><strong class="text-light">${algo}</strong></td>
                <td class="text-end font-monospace text-info">${r.encrypt_time.toFixed(3)}</td>
                <td class="text-end font-monospace text-primary">${r.decrypt_time.toFixed(3)}</td>
                <td class="text-center font-monospace">${r.key_length}</td>
                <td class="text-center"><span class="badge ${secBadge}">${r.security_level}</span></td>
                <td class="text-center"><span class="badge ${speedBadge}">${r.speed}</span></td>
            </tr>
        `);
    });
}

function updateTopPerfSummary(results) {
    const span = document.getElementById('perfLastRunSummary');
    if (!span || !results) return;
    let totalEncrypt = 0;
    Object.keys(results).forEach(algo => { totalEncrypt += results[algo].encrypt_time; });
    span.textContent = totalEncrypt.toFixed(1) + ' ms';
    span.title = 'Total encryption time across AES-256, DES, RSA-2048';
}

async function runPerformanceTest() {
    try {
        setPerfLoading(true);
        showToast('Running performance benchmark...', 'success');
        const response = await fetch('/api/performance', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ text: 'Hello World! This is a test for performance comparison across encryption algorithms.' })
        });
        const data = await response.json();
        if (data.success) {
            hidePerfEmptyState();
            renderPerfResultsTable(data.results);
            updateTopPerfSummary(data.results);

            const ctx = document.getElementById('performanceChart').getContext('2d');
            const labels = Object.keys(data.results);
            const encryptTimes = labels.map(key => data.results[key].encrypt_time);
            const decryptTimes = labels.map(key => data.results[key].decrypt_time);

            if (performanceChart) {
                performanceChart.destroy();
            }

            performanceChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Encryption Time (ms)',
                            data: encryptTimes,
                            backgroundColor: 'rgba(25, 135, 84, 0.7)',
                            borderColor: 'rgba(25, 135, 84, 1)',
                            borderWidth: 1
                        },
                        {
                            label: 'Decryption Time (ms)',
                            data: decryptTimes,
                            backgroundColor: 'rgba(13, 110, 253, 0.7)',
                            borderColor: 'rgba(13, 110, 253, 1)',
                            borderWidth: 1
                        }
                    ]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            labels: { color: '#fff' }
                        }
                    },
                    scales: {
                        y: { ticks: { color: '#fff' }, grid: { color: 'rgba(255,255,255,0.1)' } },
                        x: { ticks: { color: '#fff' }, grid: { color: 'rgba(255,255,255,0.1)' } }
                    }
                }
            });
            showToast('Benchmark complete! See chart and results below.', 'success');
        } else {
            showToast('Benchmark returned an error', 'error');
        }
    } catch (e) {
        showToast('Failed to run benchmark', 'error');
    } finally {
        setPerfLoading(false);
    }
}

// Download key
function downloadKey(elementId, filename) {
    const el = document.getElementById(elementId);
    if (el && el.value) {
        const blob = new Blob([el.value], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
        showToast('Download started', 'success');
    }
}

// Trigger file upload for key
function uploadKey(elementId) {
    const fileInput = document.getElementById(elementId + '_file');
    if (fileInput) {
        fileInput.value = '';
        fileInput.click();
    } else {
        showToast('File upload not available', 'error');
    }
}

// Handle uploaded key file
function handleFileUpload(event, targetElementId) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        const content = e.target.result;
        if (content && content.length > 0) {
            const target = document.getElementById(targetElementId);
            if (target) {
                target.value = content.trim();
                showToast(`File "${file.name}" loaded successfully`, 'success');
            } else {
                showToast('Target field not found', 'error');
            }
        } else {
            showToast('File is empty', 'error');
        }
    };
    reader.onerror = function() {
        showToast('Failed to read file', 'error');
    };
    reader.readAsText(file);
}

// Delete history entry
async function deleteHistoryEntry(id) {
    if (confirm('Delete this entry?')) {
        try {
            const response = await fetch('/api/history/delete/' + id, {
                method: 'DELETE',
                headers: {
                    'X-CSRFToken': getCsrfToken()
                }
            });
            const data = await response.json();
            if (data.success) {
                location.reload();
            }
        } catch (e) {
            showToast('Failed to delete entry', 'error');
        }
    }
}

// Clear history
async function clearHistory() {
    if (confirm('Clear all history?')) {
        try {
            const response = await fetch('/api/history/clear', {
                method: 'DELETE',
                headers: {
                    'X-CSRFToken': getCsrfToken()
                }
            });
            const data = await response.json();
            if (data.success) {
                location.reload();
            }
        } catch (e) {
            showToast('Failed to clear history', 'error');
        }
    }
}

// Export history
function exportHistory() {
    window.location.href = '/api/history/export';
}

/* ================================================================
   Rainbow / Hash Lookup (educational)
   ================================================================ */

// Tiny pure-JS hashers used only for demo buttons (so users can click a
// demo and the correct hash is computed + populated client-side,
// matching whatever algo the user wants to try).
function _md5Hex(s) {
    // Trust the backend when "looking up"; this is just for the demo
    // populating buttons. Fallback to the hash-generator route if we ever
    // want to be 100% accurate, but for the 4 demo candidates the backend
    // rainbow table covers them regardless.
    const hex = s.split('').reduce((a, c) => (((a << 5) - a) + c.charCodeAt(0)) | 0, 0);
    // Not a real MD5 — placeholder; we'll call backend to compute real hashes
    // in populateRainbowDemo below.
    return '0'.repeat(32 - Math.abs(hex).toString(16).length) + Math.abs(hex).toString(16);
}

// Compute a real hash via backend (for the "Try:" quick-buttons) so we can
// fill either md5 / sha256 / sha512 — user picks by input length.
async function _hashTextWithAlgo(text, algo) {
    const res = await fetch('/api/hash/' + algo, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({ text })
    });
    const data = await res.json();
    return data && data.success ? data.hash : null;
}

/**
 * Populate rainbow lookup demo: compute the SHA-256 of a candidate and
 * paste it into the input box. SHA-256 chosen because it's the most
 * common real-world hash users will want to demo (MD5 is deprecated).
 */
async function populateRainbowDemo(candidate) {
    const inputEl = document.getElementById('rainbowHashInput');
    if (!inputEl) return;
    try {
        inputEl.value = '';
        const h = await _hashTextWithAlgo(candidate, 'sha256');
        if (h) {
            inputEl.value = h;
            updateRainbowAlgoBadges(h);
            showToast('Hash of "' + candidate + '" pasted. Click "Look Up".', 'success');
        } else {
            showToast('Failed to compute demo hash', 'error');
        }
    } catch (e) {
        showToast('Failed to compute demo hash', 'error');
    }
}

/**
 * Visually highlight which of the 3 algorithms matches the pasted hash
 * by length + hex validity.
 */
function updateRainbowAlgoBadges(inputHash) {
    const box = document.getElementById('rainbowAlgoBadge');
    if (!box) return;

    const raw = (inputHash || '').trim().toLowerCase().replace(/^0x/, '');
    const isHex = /^[0-9a-f]*$/.test(raw);
    const len = raw.length;

    const detected = {
        md5:    isHex && len === 32,
        sha256: isHex && len === 64,
        sha512: isHex && len === 128,
    };

    const labels = [
        { key: 'md5',    title: 'MD5' },
        { key: 'sha256', title: 'SHA-256' },
        { key: 'sha512', title: 'SHA-512' },
    ];

    box.innerHTML = labels.map(l => {
        const active = detected[l.key];
        const badgeCls = active
            ? 'badge bg-success text-white rounded-pill text-start small shadow-sm'
            : 'badge bg-secondary rounded-pill text-start small opacity-75';
        const icon = active ? 'fa-circle-check' : 'fa-circle-question';
        const lenHint = l.key === 'md5' ? '32' : l.key === 'sha256' ? '64' : '128';
        return `
            <span class="${badgeCls}">
                <i class="fas ${icon} me-1"></i>${l.title} — ${lenHint} chars
            </span>`;
    }).join('');
}

function _setRainbowLookupLoading(isLoading) {
    const btn = document.getElementById('rainbowLookupBtn');
    const icon = document.getElementById('rainbowLookupIcon');
    const label = document.getElementById('rainbowLookupLabel');
    if (!btn) return;
    btn.disabled = isLoading;
    if (isLoading) {
        if (icon) {
            icon.classList.remove('fa-magnifying-glass');
            icon.classList.add('fa-sync-alt', 'fa-spin');
        }
        if (label) label.textContent = 'Looking up...';
    } else {
        if (icon) {
            icon.classList.remove('fa-sync-alt', 'fa-spin');
            icon.classList.add('fa-magnifying-glass');
        }
        if (label) label.textContent = 'Look Up';
    }
}

function renderRainbowResult(payload) {
    const card = document.getElementById('rainbowResultCard');
    if (!card) return;
    card.classList.remove('d-none');

    const header = document.getElementById('rainbowResultHeader');
    const iconEl = document.getElementById('rainbowResultIcon');
    const titleEl = document.getElementById('rainbowResultTitle');
    const hashEl = document.getElementById('rainbowResHash');
    const algoEl = document.getElementById('rainbowResAlgo');
    const categoryEl = document.getElementById('rainbowResCategory');
    const plainEl = document.getElementById('rainbowResPlain');
    const notesEl = document.getElementById('rainbowResNotes');
    const warnBox = document.getElementById('rainbowResWarning');
    const warnText = document.getElementById('rainbowResWarningText');

    if (!payload) return;
    const found = !!payload.found;

    // Header styling + cyber-themed catchy titles
    if (header) {
        header.classList.remove('bg-success-subtle', 'bg-danger-subtle', 'bg-info-subtle',
            'text-success-emphasis', 'text-danger-emphasis', 'text-info-emphasis',
            'border-success', 'border-danger', 'border-info',
            'cyber-header-pwned', 'cyber-header-secure', 'animate-pulse-neon');
    }
    // Also reset glow on outer result card
    card.classList.remove('cyber-pwned-glow', 'cyber-secure-glow');

    if (found) {
        if (header) {
            header.classList.add('cyber-header-pwned', 'animate-pulse-neon');
        }
        card.classList.add('cyber-pwned-glow');
        if (iconEl) {
            iconEl.className = 'fas fa-bug me-1 text-danger-emphasis';
        }
        if (titleEl) {
            titleEl.innerHTML =
                '<span class="badge bg-black-50 border border-danger rounded-pill me-2 px-3 py-1 text-danger">'
                + '<i class="fas fa-skull-crossbones me-1"></i>PWNED</span>'
                + '<span class="fw-bold">Hash cracked — plaintext recovered from dictionary dump</span>'
                + '<span class="d-none d-sm-inline text-danger-emphasis opacity-75 ms-2 small">'
                + '  // password exists in billions of leaked records'
                + '</span>';
        }
    } else {
        if (header) {
            header.classList.add('cyber-header-secure');
        }
        card.classList.add('cyber-secure-glow');
        if (iconEl) {
            iconEl.className = 'fas fa-shield-virus me-1 text-success';
        }
        if (titleEl) {
            titleEl.innerHTML =
                '<span class="badge bg-black-50 border border-success rounded-pill me-2 px-3 py-1 text-success">'
                + '<i class="fas fa-check-double me-1"></i>CLEAN</span>'
                + '<span class="fw-bold">No dictionary match — this input resists common wordlist attacks</span>'
                + '<span class="d-none d-sm-inline text-success opacity-75 ms-2 small">'
                + '  // not found in ~' + ((payload.rainbow_size && payload.rainbow_size.unique_plaintexts) || 0) + ' precomputed entries'
                + '</span>';
        }
    }

    if (hashEl) hashEl.textContent = payload.input_hash || '—';
    if (algoEl) {
        const algoBadge = (payload.algo_detected || 'unknown').toLowerCase();
        const cls = algoBadge === 'md5' ? 'badge bg-warning text-dark'
            : algoBadge === 'sha256' ? 'badge bg-success'
            : algoBadge === 'sha512' ? 'badge bg-info text-dark'
            : 'badge bg-secondary';
        algoEl.innerHTML = `<span class="${cls}">${(payload.algo_detected || 'unknown').toUpperCase()}</span>`;
    }
    if (categoryEl) {
        categoryEl.textContent = found ? (payload.category || '—') : 'Not in dictionary';
    }
    if (plainEl) {
        plainEl.value = found ? (payload.plaintext || '') : '';
    }
    if (notesEl) {
        notesEl.textContent = found
            ? (payload.notes || '—')
            : 'The hash did not match any of the ' +
              ((payload.rainbow_size && payload.rainbow_size.unique_plaintexts) || 0) +
              ' precomputed dictionary entries. For strong unique inputs, dictionary ' +
              'and rainbow-table attacks are infeasible.';
    }
    if (warnText) {
        warnText.textContent = payload.educational_warning || '';
    }
    if (warnBox) warnBox.classList.remove('d-none');
}

async function runRainbowLookup() {
    const inputEl = document.getElementById('rainbowHashInput');
    if (!inputEl) return;
    const raw = (inputEl.value || '').trim();
    if (!raw) {
        showToast('Paste a hash first (or click a Try: button above).', 'warning');
        return;
    }
    try {
        _setRainbowLookupLoading(true);
        const res = await fetch('/api/hash/lookup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ hash: raw })
        });
        const data = await res.json();
        updateRainbowAlgoBadges(raw);
        if (data && (data.success || data.found !== undefined)) {
            renderRainbowResult(data);
            if (data.found) {
                showToast('Match found: ' + data.plaintext, 'warning');
            } else {
                showToast('No match — great, this is a strong input!', 'success');
            }
        } else {
            showToast(data && data.error ? data.error : 'Lookup failed', 'error');
        }
    } catch (e) {
        showToast('Network error during lookup', 'error');
    } finally {
        _setRainbowLookupLoading(false);
    }
}

// Timestamp to string (Jinja2 filter replacement)
if (typeof module === 'undefined') {
    // Browser-only code
    document.addEventListener('DOMContentLoaded', () => {
        // Initialize
        const timestampEls = document.querySelectorAll('[data-timestamp]');
        timestampEls.forEach(el => {
            const ts = parseInt(el.dataset.timestamp);
            el.textContent = new Date(ts * 1000).toLocaleString();
        });

        if (document.getElementById('perfRunBtn')) {
            setTimeout(() => {
                runPerformanceTest();
            }, 350);
        }

        // ---- Rainbow lookup wiring -------------------------------------
        const rainbowInput = document.getElementById('rainbowHashInput');
        if (rainbowInput) {
            rainbowInput.addEventListener('input', () => {
                updateRainbowAlgoBadges(rainbowInput.value);
            });
            rainbowInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    runRainbowLookup();
                }
            });
            updateRainbowAlgoBadges(rainbowInput.value);
        }
    });
}
