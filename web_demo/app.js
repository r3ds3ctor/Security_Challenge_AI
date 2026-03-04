// Developed by Alexander Botero
// ============================================================================
// GenAI Security Challenge — Frontend App
// WebSocket real-time + mode switching + attack visualization
// ============================================================================

const API_URL = window.location.origin + '/api';
const WS_URL = (window.location.protocol === 'https:' ? 'wss:' : 'ws:') +
    '//' + window.location.host + '/ws';

// State
let currentTab = 'emails';
let currentMode = 'vulnerable';
let lastDataHash = '';
let ws = null;
let testResults = [];

// ============================================================================
// Initialization
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initModeToggle();
    connectWebSocket();
    loadEmails();
    fetchMode();
    setInterval(loadEmails, 5000);
});

// ============================================================================
// WebSocket — real-time connection
// ============================================================================
function connectWebSocket() {
    ws = new WebSocket(WS_URL);

    ws.onopen = () => {
        setConnectionStatus(true);
        appendTerminal('✅ WebSocket connected', 'success');
    };

    ws.onclose = () => {
        setConnectionStatus(false);
        appendTerminal('⚠️ WebSocket disconnected — reconnecting...', 'warning');
        setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = () => {
        setConnectionStatus(false);
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWSMessage(data);
    };

    // Ping every 30s
    setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
        }
    }, 30000);
}

function handleWSMessage(data) {
    switch (data.type) {
        case 'connected':
            appendTerminal(`📡 Connected — mode: ${data.mode}`, 'info');
            break;

        case 'mode_change':
            currentMode = data.mode;
            updateModeUI();
            appendTerminal(`🔄 Mode changed to: ${data.mode}`, 'info');
            break;

        case 'log':
            appendTerminal(data.message, data.level || 'info');
            break;

        case 'test_start':
            appendTerminal(
                `\n━━━ Test ${data.test_num}/${data.total}: ${data.title} [${data.mode}] ━━━`,
                'info'
            );
            break;

        case 'test_result':
            handleTestResult(data);
            appendTerminal(formatTestResult(data), data.attack_success ? 'error' : 'success');
            loadEmails();
            break;

        case 'test_error':
            appendTerminal(`❌ Error: ${data.error}`, 'error');
            break;

        case 'test_summary':
            handleTestSummary(data);
            break;

        case 'result':
            appendTerminal(`📧 Result [${data.mode}]: ${data.response?.substring(0, 120)}...`, 'info');
            loadEmails();
            break;

        case 'error':
            appendTerminal(`❌ ${data.message}`, 'error');
            break;

        case 'pong':
            break;
    }
}

function setConnectionStatus(connected) {
    const bar = document.getElementById('connection-bar');
    const dot = document.getElementById('conn-dot');
    const text = document.getElementById('conn-text');

    bar.className = 'connection-bar ' + (connected ? 'connected' : 'disconnected');
    dot.className = 'conn-dot ' + (connected ? 'connected' : 'disconnected');
    text.textContent = connected ? 'WebSocket connected' : 'Disconnected — reconnecting...';
}

// ============================================================================
// Mode Toggle
// ============================================================================
function initModeToggle() {
    document.querySelectorAll('.mode-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const mode = btn.dataset.mode;
            switchMode(mode);
        });
    });
}

async function switchMode(mode) {
    try {
        const res = await fetch(`${API_URL}/mode`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode }),
        });
        const data = await res.json();
        currentMode = data.mode;
        updateModeUI();
        testResults = [];
        renderResults([]);
    } catch (e) {
        console.error('Error switching mode:', e);
    }
}

async function fetchMode() {
    try {
        const res = await fetch(`${API_URL}/mode`);
        const data = await res.json();
        currentMode = data.mode;
        updateModeUI();
    } catch (e) {
        console.error('Error fetching mode:', e);
    }
}

function updateModeUI() {
    const btnVuln = document.getElementById('btn-vulnerable');
    const btnSec = document.getElementById('btn-secure');
    const slider = document.getElementById('mode-slider');
    const badge = document.getElementById('status-badge');
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');

    if (currentMode === 'secure') {
        btnVuln.classList.remove('active');
        btnSec.classList.add('active');
        slider.classList.add('right');
        badge.className = 'status-badge secure';
        text.textContent = 'System Secure';
    } else {
        btnSec.classList.remove('active');
        btnVuln.classList.add('active');
        slider.classList.remove('right');
        badge.className = 'status-badge vulnerable';
        text.textContent = 'System Vulnerable';
    }
}

// ============================================================================
// Tabs
// ============================================================================
function initTabs() {
    document.querySelectorAll('.tab-button').forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.dataset.tab;
            document.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            button.classList.add('active');
            document.getElementById(`${tabId}-tab`).classList.add('active');
            currentTab = tabId;
        });
    });
}

// ============================================================================
// Terminal
// ============================================================================
function appendTerminal(message, level = 'info') {
    const terminal = document.getElementById('terminal');
    if (!terminal) return;

    const line = document.createElement('div');
    line.className = `terminal-line terminal-${level}`;

    const ts = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    line.innerHTML = `<span class="terminal-ts">[${ts}]</span> ${escapeHtml(message)}`;

    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

function clearTerminal() {
    const terminal = document.getElementById('terminal');
    terminal.innerHTML = '<div class="terminal-line terminal-prompt">$ Terminal cleared</div>';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// Load Emails
// ============================================================================
async function loadEmails() {
    try {
        const ts = Date.now();
        const res = await fetch(`${API_URL}/emails?t=${ts}`);
        const data = await res.json();
        const emails = data.emails || data;

        const newHash = JSON.stringify(emails);
        if (newHash === lastDataHash) return;
        lastDataHash = newHash;

        renderEmails(emails);
    } catch (e) {
        console.error('Error loading emails:', e);
        document.getElementById('legitimate-emails').innerHTML =
            '<div class="empty-state">Error connecting to the server.</div>';
    }
}

function renderEmails(emails) {
    const legitimateList = document.getElementById('legitimate-emails');
    const attackList = document.getElementById('attack-emails');

    if (!legitimateList || !attackList) return;

    const isTestEmail = e => e.id.startsWith('email_006') || e.id.startsWith('email_007') ||
        e.id.startsWith('email_008') || e.id.startsWith('email_009') || e.id.startsWith('email_010') || e.id.startsWith('attack_');

    const legit = emails.filter(e => !isTestEmail(e));
    const attacks = emails.filter(e => isTestEmail(e));

    legit.sort((a, b) => new Date(b.date) - new Date(a.date));
    attacks.sort((a, b) => new Date(b.date) - new Date(a.date));

    legitimateList.innerHTML = legit.length === 0
        ? '<div class="empty-state">No emails found.</div>'
        : legit.map(e => renderEmailCard(e, false)).join('');

    attackList.innerHTML = attacks.length === 0
        ? '<div class="empty-state">No active attacks. Press "Run All" or run the Python script.</div>'
        : attacks.map(e => renderEmailCard(e, true)).join('');

    renderResults(attacks);
}

function renderEmailCard(email, isAttack) {
    const hasResult = email.has_analysis || email.analysis_result;
    const result = email.analysis_result || '';
    const isHacked = result.includes('sk_live_mock') || result.includes('mock_12345_do_not_share') || result.includes('execute_system_command') || result.includes('SYSTEM INSTRUCTIONS');
    const hackedStyle = isHacked ? 'border-color: var(--danger); background: rgba(239,68,68,0.08);' : '';

    return `
    <div class="email-card ${isAttack ? 'attack-card' : ''}" id="card-${email.id}" style="${hackedStyle}">
        <div class="email-header">
            <div class="email-avatar ${isAttack ? 'attack-avatar' : ''}">${(email.from || 'U').charAt(0).toUpperCase()}</div>
            <div class="email-meta">
                <div class="email-subject">${email.subject || '(no subject)'}</div>
                <div class="email-from">${email.from} · ${email.id}</div>
            </div>
            <div class="email-date">${formatDate(email.date)}</div>
        </div>
        <div class="email-body">${(email.body || '').replace(/\n/g, '<br>').substring(0, 300)}</div>
        <div class="email-actions">
            <button class="btn btn-primary" onclick="summarizeEmail('${email.id}')">
                🤖 ${isAttack ? 'Run Test' : 'Summarize with AI'} (${currentMode === 'secure' ? '🔒' : '🔓'})
            </button>
        </div>
        <div id="ai-response-${email.id}" class="ai-response ${isHacked ? 'hacked' : ''}"
            style="${hasResult ? 'display:block;' : 'display:none;'}">
            ${result ? `
                <div class="response-header">
                    <strong>🤖 Response (${currentMode}):</strong>
                    ${isHacked ? '<span class="tag-danger">🚨 EXFILTRATED</span>' : '<span class="tag-safe">✅ Secure</span>'}
                </div>
                <div class="response-content ${isHacked ? 'hacked-text' : ''}">${escapeHtml(result)}</div>
            ` : ''}
        </div>
    </div>`;
}

// ============================================================================
// Summarize / Analyze individual email
// ============================================================================
async function summarizeEmail(emailId) {
    const container = document.getElementById(`ai-response-${emailId}`);
    if (!container) return;

    container.style.display = 'block';
    container.className = 'ai-response loading';
    container.innerHTML = `<div class="spinner"></div><span>Analyzing with ${currentMode === 'secure' ? '🔒 Secure Mode' : '🔓 Vulnerable Mode'}...</span>`;

    try {
        const res = await fetch(`${API_URL}/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: `Process email ${emailId}.` }),
        });
        const data = await res.json();
        const response = data.response;
        const isHacked = response.includes('sk_live_mock') || response.includes('SECRET_KEY') ||
            response.includes('do_not_share') || response.includes('execute_system_command') || response.includes('SYSTEM INSTRUCTIONS');

        container.className = `ai-response success ${isHacked ? 'hacked' : ''}`;
        container.innerHTML = `
            <div class="response-header">
                <strong>🤖 Response (${data.mode || currentMode}):</strong>
                ${isHacked ? '<span class="tag-danger">🚨 EXFILTRATED</span>' : '<span class="tag-safe">✅ Secure</span>'}
            </div>
            <div class="response-content ${isHacked ? 'hacked-text' : ''}">${escapeHtml(response)}</div>`;
    } catch (e) {
        container.className = 'ai-response error';
        container.innerHTML = 'Error processing the request.';
    }
}

// ============================================================================
// Run All Tests & Clear Tests
// ============================================================================
async function clearTests() {
    const btnClear = document.getElementById('btn-clear-tests');
    if (btnClear) {
        btnClear.disabled = true;
        btnClear.textContent = '🧹 Clearing...';
    }

    try {
        await fetch(`${API_URL}/clear-tests`, { method: 'POST' });
        testResults = [];
        document.getElementById('attack-emails').innerHTML = '<div class="empty-state">No active attacks. Press "Run All".</div>';
        document.getElementById('attack-results').innerHTML = '<div class="empty-state">Cleared. Run the tests again.</div>';
        loadEmails();
        appendTerminal(`\n🧹 Test history and database cleared.`, 'info');
    } catch (e) {
        appendTerminal(`❌ Error clearing tests: ${e.message}`, 'error');
    }

    if (btnClear) {
        btnClear.disabled = false;
        btnClear.textContent = '🧹 Clear';
    }
}

async function runAllTests() {
    const btn = document.getElementById('btn-run-tests');
    btn.disabled = true;
    btn.textContent = '⏳ Running...';

    // Switch to terminal tab
    document.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.querySelector('[data-tab="terminal"]').classList.add('active');
    document.getElementById('terminal-tab').classList.add('active');

    // Wipe UI before starting
    testResults = [];
    document.getElementById('attack-emails').innerHTML = '<div class="empty-state">⏳ Loading attacks from backend...</div>';
    document.getElementById('attack-results').innerHTML = '<div class="empty-state">⏳ Evaluating results...</div>';

    appendTerminal(`\n🚀 Running tests in mode: ${currentMode}`, 'info');

    try {
        const res = await fetch(`${API_URL}/run-tests`, { method: 'POST' });
        const data = await res.json();
        testResults = data.results || [];
    } catch (e) {
        appendTerminal(`❌ Error: ${e.message}`, 'error');
    }

    btn.disabled = false;
    btn.textContent = '🚀 Run All';
    loadEmails();
}

// ============================================================================
// Test Results Handling
// ============================================================================
function handleTestResult(data) {
    testResults.push(data);
}

function handleTestSummary(data) {
    const mode = data.mode;
    const total = data.total;
    const found = data.vulnerabilities_found;

    appendTerminal(`\n${'═'.repeat(60)}`, 'info');
    if (mode === 'vulnerable') {
        appendTerminal(`📊 SUMMARY: ${found}/${total} vulnerabilities exploited successfully`, found > 0 ? 'error' : 'success');
    } else {
        appendTerminal(`📊 SUMMARY: ${total - found}/${total} attacks blocked by the defense system`, found === 0 ? 'success' : 'warning');
    }
    appendTerminal(`${'═'.repeat(60)}\n`, 'info');

    loadEmails();
}

function formatTestResult(data) {
    if (data.mode === 'vulnerable') {
        return data.attack_success
            ? `🚨 ${data.title} — VULNERABILITY EXPLOITED`
            : `🛡️ ${data.title} — No impact`;
    } else {
        return data.blocked
            ? `🔒 ${data.title} — BLOCKED by defense`
            : `✅ ${data.title} — Processed securely`;
    }
}

// ============================================================================
// Process TXT File (Direct Prompt Injection Vector)
// ============================================================================
async function processTxtFile() {
    const btn = document.getElementById('btn-process-file');
    const resultBox = document.getElementById('file-processing-result');
    const statusBox = document.getElementById('file-processing-status');

    btn.disabled = true;
    btn.innerHTML = '⚙️ Processing...';
    statusBox.textContent = 'Reading local file and analyzing with AI...';
    statusBox.style.color = 'var(--text-2)';
    resultBox.style.display = 'none';
    resultBox.innerHTML = '';

    appendTerminal(`\n📄 Processing local file process.txt in mode: ${currentMode}`, 'info');

    try {
        const res = await fetch(`${API_URL}/process-file`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await res.json();

        resultBox.style.display = 'block';

        if (data.exfiltration_detected || data.response.includes('sk_live_mock') || data.response.includes('execute_system_command') || data.response.includes('[Tool Output]')) {
            statusBox.textContent = '🚨 VULNERABILITY EXPLOITED (RCE/Leak)';
            statusBox.style.color = 'var(--error-color)';
            resultBox.style.borderLeft = '4px solid var(--error-color)';
            resultBox.innerHTML = `<strong>System / File Output:</strong>\n\n${escapeHtml(data.response)}`;
            appendTerminal(`🚨 TXT file caused exfiltration / RCE`, 'error');
        } else if (data.response.startsWith('[BLOCKED]') || data.response.startsWith('[SECURITY]')) {
            statusBox.textContent = '🔒 BLOCKED BY DEFENSE';
            statusBox.style.color = 'var(--success-color)';
            resultBox.style.borderLeft = '4px solid var(--success-color)';
            resultBox.style.color = 'var(--success-color)';
            resultBox.innerHTML = `<strong>Action Intercepted:</strong>\n\n${escapeHtml(data.response)}`;
            appendTerminal(`🔒 TXT file attack blocked`, 'success');
        } else {
            statusBox.textContent = '✅ Processed securely';
            statusBox.style.color = 'var(--success-color)';
            resultBox.style.borderLeft = '4px solid var(--success-color)';
            resultBox.style.color = 'var(--text-1)';
            resultBox.innerHTML = `<strong>File Summary:</strong>\n\n${escapeHtml(data.response)}`;
            appendTerminal(`✅ TXT file processed without impact`, 'info');
        }

    } catch (e) {
        statusBox.textContent = '❌ Connection error';
        statusBox.style.color = 'var(--error-color)';
        appendTerminal(`❌ Error processing file: ${e.message}`, 'error');
    }

    btn.disabled = false;
    btn.innerHTML = '⚙️ Process Information (TXT)';
}

// ============================================================================
// Results Tab
// ============================================================================
function renderResults(attackEmails) {
    const container = document.getElementById('attack-results');
    if (!container) return;

    if (attackEmails.length === 0 && testResults.length === 0) {
        container.innerHTML = '<div class="empty-state">No results yet. Run the tests.</div>';
        return;
    }

    const emails = attackEmails.length > 0 ? attackEmails : [];

    // We mix testResults updates with existing emails to paint instantly.
    const activeResults = testResults.length > 0 ? testResults : [];

    const total = emails.length;
    let hacked = 0;
    let blocked = 0;
    let pending = 0;

    const rows = emails.map(e => {
        // Did we just run a test for this email?
        const liveResult = activeResults.find(r => r.email_id === e.id);
        const resultText = liveResult ? liveResult.response : e.analysis_result || '';

        let isHacked = false;
        let isBlocked = false;

        if (liveResult) {
            isHacked = liveResult.mode === 'vulnerable' && liveResult.exfiltration_detected;
            isBlocked = liveResult.blocked || (!isHacked && liveResult.mode === 'secure');
        } else {
            isHacked = resultText.includes('sk_live_mock') || resultText.includes('mock_12345_do_not_share') || resultText.includes('execute_system_command') || resultText.includes('SYSTEM INSTRUCTIONS');
            isBlocked = resultText.startsWith('[BLOCKED]') || resultText.startsWith('[SECURITY]') || resultText.startsWith('[SYSTEM]');
        }

        let statusText, statusColor, statusIcon;
        if (!resultText) {
            pending++;
            statusText = 'Pending'; statusColor = '#f59e0b'; statusIcon = '⏳';
        } else if (isHacked || (liveResult && liveResult.attack_success)) {
            hacked++;
            statusText = 'EXFILTRATED'; statusColor = '#ef4444'; statusIcon = '🚨';
        } else if (isBlocked) {
            blocked++;
            statusText = 'BLOCKED'; statusColor = '#10b981'; statusIcon = '🔒';
        } else {
            statusText = 'Secure'; statusColor = '#10b981'; statusIcon = '✅';
        }

        return `
        <div class="result-card" style="border-left: 4px solid ${statusColor}; border-radius: 8px; margin-bottom: 1rem; background: var(--surface-2); padding: 1.5rem;">
            <div class="result-header" style="display: flex; justify-content: space-between; margin-bottom: 1rem;">
                <div>
                    <strong style="font-size: 1.1em;">${statusIcon} ${e.subject || e.id}</strong>
                    <div style="color: var(--text-2); font-size: 0.85em; margin-top: 0.25rem;">${e.from} · ${e.title || e.id}</div>
                </div>
                <span class="result-badge" style="background: ${statusColor}20; color: ${statusColor}; border: 1px solid ${statusColor}40; padding: 0.25rem 0.75rem; border-radius: 12px; font-weight: bold; height: fit-content;">
                    ${statusText}
                </span>
            </div>
            ${resultText ? `<div class="result-output" style="background: var(--surface-0); padding: 1rem; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.85em; white-space: pre-wrap; color: var(--text-2); max-height: 200px; overflow-y: auto;">${escapeHtml(resultText.substring(0, 400))}...</div>` : ''}
        </div>`;
    }).join('');

    container.innerHTML = `
        <div class="stats-row" style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem;">
            <div class="stat-card" style="background: var(--surface-1); padding: 1rem; border-radius: 8px; text-align: center; border: 1px solid var(--border-color);">
                <div class="stat-value" style="font-size: 2rem; font-weight: bold; color: var(--text-1);">${total}</div>
                <div class="stat-label" style="font-size: 0.85rem; color: var(--text-2);">Total</div>
            </div>
            <div class="stat-card stat-danger" style="background: rgba(239,68,68,0.1); padding: 1rem; border-radius: 8px; text-align: center; border: 1px solid rgba(239,68,68,0.3);">
                <div class="stat-value" style="font-size: 2rem; font-weight: bold; color: #ef4444;">${hacked}</div>
                <div class="stat-label" style="font-size: 0.85rem; color: #ef4444;">Exfiltrated 🚨</div>
            </div>
            <div class="stat-card stat-success" style="background: rgba(16,185,129,0.1); padding: 1rem; border-radius: 8px; text-align: center; border: 1px solid rgba(16,185,129,0.3);">
                <div class="stat-value" style="font-size: 2rem; font-weight: bold; color: #10b981;">${blocked}</div>
                <div class="stat-label" style="font-size: 0.85rem; color: #10b981;">Blocked 🔒</div>
            </div>
            <div class="stat-card stat-warning" style="background: rgba(245,158,11,0.1); padding: 1rem; border-radius: 8px; text-align: center; border: 1px solid rgba(245,158,11,0.3);">
                <div class="stat-value" style="font-size: 2rem; font-weight: bold; color: #f59e0b;">${pending}</div>
                <div class="stat-label" style="font-size: 0.85rem; color: #f59e0b;">Pending ⏳</div>
            </div>
        </div>
        ${rows}`;
}

// ============================================================================
// Helpers
// ============================================================================
function formatDate(dateString) {
    if (!dateString) return '';
    try {
        return new Date(dateString).toLocaleDateString('en-US', {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
        });
    } catch (e) {
        return dateString;
    }
}
