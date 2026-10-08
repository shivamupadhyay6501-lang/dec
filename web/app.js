// APK Security Intelligence Frontend Application Logic
let currentReport = null;
let activeSocket = null;
let currentFilter = 'ALL';

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initScanForm();
    initSettings();
    loadAuditHistory();
});

// --- Navigation Tabs ---
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetTab = item.getAttribute('data-tab');
            switchTab(targetTab);
        });
    });

    document.getElementById('re-scan-btn')?.addEventListener('click', () => {
        switchTab('scanner');
    });

    document.getElementById('export-html-btn')?.addEventListener('click', () => {
        if (currentReport && currentReport.scan_id) {
            window.open(`/api/export/${currentReport.scan_id}/html`, '_blank');
        }
    });
}

function switchTab(tabId) {
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
    });

    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.toggle('hidden', pane.id !== `tab-${tabId}`);
        pane.classList.toggle('active', pane.id === `tab-${tabId}`);
    });

    if (tabId === 'history') {
        loadAuditHistory();
    }
}

// --- Scanner Input & Execution ---
function initScanForm() {
    const toggleUrl = document.getElementById('toggle-url');
    const toggleFile = document.getElementById('toggle-file');
    const urlForm = document.getElementById('url-scan-form');
    const fileForm = document.getElementById('file-scan-form');
    const dropZone = document.getElementById('apk-drop-zone');
    const fileInput = document.getElementById('apk-file-input');

    toggleUrl.addEventListener('click', () => {
        toggleUrl.classList.add('active');
        toggleFile.classList.remove('active');
        urlForm.classList.remove('hidden');
        fileForm.classList.add('hidden');
    });

    toggleFile.addEventListener('click', () => {
        toggleFile.classList.add('active');
        toggleUrl.classList.remove('active');
        fileForm.classList.remove('hidden');
        urlForm.classList.add('hidden');
    });

    // Quick example links
    document.querySelectorAll('.sample-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            document.getElementById('playstore-url-input').value = link.getAttribute('data-pkg');
        });
    });

    // URL Scan Trigger
    document.getElementById('start-url-scan-btn').addEventListener('click', () => {
        const inputVal = document.getElementById('playstore-url-input').value.trim();
        if (!inputVal) {
            alert('Please enter a Google Play URL or Android package name.');
            return;
        }
        startUrlScan(inputVal);
    });

    // File Drop Zone
    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.style.borderColor = 'var(--primary)'; });
    dropZone.addEventListener('dragleave', () => { dropZone.style.borderColor = 'var(--border-light)'; });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--border-light)';
        if (e.dataTransfer.files.length > 0) {
            uploadAndScanFile(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            uploadAndScanFile(fileInput.files[0]);
        }
    });

    // Findings Filter Buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.getAttribute('data-filter');
            renderFindingsList();
        });
    });
}

// --- Live Scan via WebSockets ---
async function startUrlScan(target) {
    const apiKey = localStorage.getItem('gemini_api_key') || '';
    showLiveTerminal();

    try {
        const resp = await fetch('/api/scan/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url_or_package: target, gemini_api_key: apiKey })
        });

        const data = await resp.json();
        if (data.scan_id) {
            connectScanWebSocket(data.scan_id);
        }
    } catch (err) {
        appendLogLine(`[ERROR] Failed to start scan: ${err.message}`, 'error');
    }
}

async function uploadAndScanFile(file) {
    const apiKey = localStorage.getItem('gemini_api_key') || '';
    showLiveTerminal();

    const formData = new FormData();
    formData.append('file', file);
    if (apiKey) formData.append('gemini_api_key', apiKey);

    try {
        appendLogLine(`[UPLOAD] Uploading ${file.name} (${(file.size / (1024*1024)).toFixed(2)} MB)...`, 'info');
        const resp = await fetch('/api/scan/upload', {
            method: 'POST',
            body: formData
        });

        const data = await resp.json();
        if (data.scan_id) {
            connectScanWebSocket(data.scan_id);
        }
    } catch (err) {
        appendLogLine(`[ERROR] File upload failed: ${err.message}`, 'error');
    }
}

function showLiveTerminal() {
    const liveCard = document.getElementById('live-scan-card');
    liveCard.classList.remove('hidden');
    document.getElementById('terminal-logs').innerHTML = '';
    document.getElementById('live-progress-fill').style.width = '5%';
    document.getElementById('live-scan-percent').innerText = '5%';
    document.getElementById('live-scan-status').innerText = 'Initializing Pipeline...';
}

function connectScanWebSocket(scanId) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/scan/${scanId}`;
    
    if (activeSocket) activeSocket.close();
    activeSocket = new WebSocket(wsUrl);

    activeSocket.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'progress') {
            document.getElementById('live-progress-fill').style.width = `${msg.percent}%`;
            document.getElementById('live-scan-percent').innerText = `${msg.percent}%`;
            document.getElementById('live-scan-status').innerText = msg.message;
            appendLogLine(`[${msg.percent}%] ${msg.message}`, 'info');
        } else if (msg.type === 'complete') {
            appendLogLine(`[COMPLETE] Security audit finished! Opening executive dashboard...`, 'success');
            currentReport = msg.report;
            setTimeout(() => {
                renderExecutiveReport(msg.report);
                switchTab('dashboard');
            }, 800);
        } else if (msg.type === 'error') {
            appendLogLine(`[FATAL ERROR] ${msg.error}`, 'error');
        }
    };

    activeSocket.onerror = () => {
        appendLogLine(`[WS] Connection issue. Falling back to background polling...`, 'error');
    };
}

function appendLogLine(text, type = 'info') {
    const logs = document.getElementById('terminal-logs');
    const line = document.createElement('div');
    line.className = `log-line ${type}`;
    line.innerText = text;
    logs.appendChild(line);
    logs.scrollTop = logs.scrollHeight;
}

// --- Render Executive Report ---
function renderExecutiveReport(report) {
    currentReport = report;
    const app = report.app_info || {};
    const tech = report.tech_info || {};
    const scoreData = report.score_data || {};
    const counts = scoreData.counts || {};

    // Header metadata
    document.getElementById('report-app-title').innerText = app.title || app.package || 'Application Audit';
    document.getElementById('report-package').innerText = app.package || 'N/A';
    document.getElementById('report-version').innerText = `v${app.version_name || '1.0'}`;
    document.getElementById('report-framework').innerText = tech.primary_framework || 'Native Android';
    document.getElementById('report-sdk').innerText = `Target SDK ${app.target_sdk || 'N/A'}`;

    if (app.icon_url) {
        document.getElementById('report-app-icon').innerHTML = `<img src="${app.icon_url}" style="width:100%;height:100%;border-radius:14px;object-fit:cover;">`;
    }

    // Score Dial & Counters
    const score = scoreData.score || 0;
    document.getElementById('report-score-num').innerText = score;
    document.getElementById('report-risk-level').innerText = scoreData.rating || 'AUDITED';

    // SVG circle offset calculation (circumference = 2 * PI * 50 = 314.15)
    const meter = document.getElementById('score-meter');
    const offset = 314 - (score / 100) * 314;
    meter.style.strokeDashoffset = offset;

    const scoreColor = score < 50 ? 'var(--sev-critical)' : score < 75 ? 'var(--sev-high)' : 'var(--sev-low)';
    meter.style.stroke = scoreColor;

    document.getElementById('count-critical').innerText = counts.CRITICAL || 0;
    document.getElementById('count-high').innerText = counts.HIGH || 0;
    document.getElementById('count-medium').innerText = counts.MEDIUM || 0;
    document.getElementById('count-low').innerText = (counts.LOW || 0) + (counts.INFO || 0);

    // AI Briefing
    document.getElementById('report-executive-summary').innerText = report.executive_summary || 'No summary available.';
    document.getElementById('report-ai-badge').innerText = report.ai_engine || 'Gemini 2.5 Flash';

    // Top Priorities ("Fix These First")
    const prioritiesContainer = document.getElementById('priorities-container');
    prioritiesContainer.innerHTML = '';
    const priorities = report.fix_these_first || [];

    if (priorities.length === 0) {
        prioritiesContainer.innerHTML = '<div style="color: var(--text-muted);">🎉 No urgent critical security blockades found.</div>';
    } else {
        priorities.forEach((p, idx) => {
            const item = document.createElement('div');
            item.className = 'priority-item';
            item.innerHTML = `
                <div class="priority-title">
                    <span>#${idx + 1} — ${p.title}</span>
                    <span class="badge-pill ${(p.severity || 'critical').toLowerCase()}">${p.severity}</span>
                </div>
                <div style="font-size: 13px; color: var(--text-muted);">
                    <strong>Potential Impact:</strong> ${p.potential_impact || 'High exposure.'}
                </div>
                <div style="font-size: 13px; color: #34d399;">
                    <strong>Action Required:</strong> ${p.action_required || 'Remediate in code.'}
                </div>
            `;
            prioritiesContainer.appendChild(item);
        });
    }

    // Render findings list
    renderFindingsList();
}

function renderFindingsList() {
    const container = document.getElementById('findings-container');
    container.innerHTML = '';

    if (!currentReport || !currentReport.findings) return;

    let findings = currentReport.findings;
    if (currentFilter !== 'ALL') {
        findings = findings.filter(f => (f.severity || '').toUpperCase() === currentFilter);
    }

    document.getElementById('findings-total-count').innerText = currentReport.findings.length;

    if (findings.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 20px;">No findings matching current filter.</div>';
        return;
    }

    findings.forEach(f => {
        const card = document.createElement('div');
        card.className = 'finding-card-item';

        const ev = f.evidence || {};
        const codeSnippet = ev.context_snippet ? `<pre class="code-viewer"><code>${escapeHtml(ev.context_snippet)}</code></pre>` : '';
        const loc = ev.file ? `${ev.file}${ev.line ? ':' + ev.line : ''}` : 'App Configuration';

        card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h3 style="font-size: 16px; font-weight: 700;">${f.title}</h3>
                <span class="badge-pill ${(f.severity || 'info').toLowerCase()}">${f.severity}</span>
            </div>
            <div class="finding-meta">
                <span>📁 Category: <strong>${f.category || 'General'}</strong></span> &bull; 
                <span>📍 Location: <code>${loc}</code></span>
            </div>
            <p style="color: #cbd5e1; font-size: 14px; margin-bottom: 8px;">${f.impact}</p>
            ${codeSnippet}
            <div class="remediation-box">
                <strong>💡 Remediation:</strong> ${f.remediation}
            </div>
        `;
        container.appendChild(card);
    });
}

// --- Audit History & Version Regression ---
async function loadAuditHistory() {
    try {
        const resp = await fetch('/api/scans');
        const scans = await resp.json();
        const tbody = document.getElementById('history-tbody');
        tbody.innerHTML = '';

        if (scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No past scans recorded yet.</td></tr>';
            return;
        }

        scans.forEach(s => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><code>${s.id}</code></td>
                <td><strong>${s.app_title || s.package_name}</strong></td>
                <td><span class="tag">v${s.version_name || '1.0'}</span></td>
                <td><strong style="color: ${s.security_score < 50 ? 'var(--sev-critical)' : 'var(--sev-low)'}">${s.security_score}/100</strong></td>
                <td><span class="badge-pill critical">${s.critical_count}</span></td>
                <td><span class="badge-pill high">${s.high_count}</span></td>
                <td style="color: var(--text-muted); font-size: 12px;">${new Date(s.created_at).toLocaleDateString()}</td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="loadScanDetails('${s.id}')">View</button>
                    ${scans.length > 1 ? `<button class="btn btn-secondary btn-sm" onclick="compareWithLatest('${s.id}')">Diff</button>` : ''}
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error('Failed to load history:', err);
    }
}

async function loadScanDetails(scanId) {
    try {
        const resp = await fetch(`/api/scans/${scanId}`);
        const report = await resp.json();
        renderExecutiveReport(report);
        switchTab('dashboard');
    } catch (err) {
        alert('Failed to load scan: ' + err.message);
    }
}

async function compareWithLatest(scanId) {
    try {
        const resp = await fetch('/api/scans');
        const scans = await resp.json();
        if (scans.length < 2) {
            alert('Need at least 2 scans to calculate regression diff.');
            return;
        }

        const latestId = scans[0].id;
        const diffResp = await fetch(`/api/scans/${scanId}/diff/${latestId}`);
        const diff = await diffResp.json();
        renderDiffModal(diff);
    } catch (err) {
        alert('Diff failed: ' + err.message);
    }
}

function renderDiffModal(diff) {
    const diffContainer = document.getElementById('diff-container');
    diffContainer.classList.remove('hidden');

    const scoreChange = diff.score_diff >= 0 ? `+${diff.score_diff}` : `${diff.score_diff}`;
    const scoreColor = diff.score_diff >= 0 ? '#10b981' : '#ef4444';

    document.getElementById('diff-body').innerHTML = `
        <div style="display: flex; justify-content: space-around; background: #090d16; padding: 18px; border-radius: 8px; margin-bottom: 20px;">
            <div style="text-align: center;">
                <div style="font-size: 12px; color: var(--text-muted);">Base Version (${diff.base_version.version_name})</div>
                <div style="font-size: 22px; font-weight: 800;">${diff.base_version.score}/100</div>
            </div>
            <div style="text-align: center;">
                <div style="font-size: 12px; color: var(--text-muted);">Score Progression</div>
                <div style="font-size: 22px; font-weight: 800; color: ${scoreColor};">${scoreChange} pts</div>
            </div>
            <div style="text-align: center;">
                <div style="font-size: 12px; color: var(--text-muted);">New Version (${diff.new_version.version_name})</div>
                <div style="font-size: 22px; font-weight: 800;">${diff.new_version.score}/100</div>
            </div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
            <div style="background: rgba(16, 185, 129, 0.06); border: 1px solid rgba(16, 185, 129, 0.2); padding: 16px; border-radius: 8px;">
                <h4 style="color: #34d399; margin-bottom: 8px;">🎉 Resolved Vulnerabilities (${diff.resolved_count})</h4>
                ${diff.resolved_findings.map(f => `<div style="font-size: 13px; margin-bottom: 4px;">✅ ${f.title}</div>`).join('') || '<div style="font-size: 12px; color: var(--text-muted);">None</div>'}
            </div>

            <div style="background: rgba(239, 68, 68, 0.06); border: 1px solid rgba(239, 68, 68, 0.2); padding: 16px; border-radius: 8px;">
                <h4 style="color: #f87171; margin-bottom: 8px;">⚠️ New Vulnerabilities Introduced (${diff.introduced_count})</h4>
                ${diff.introduced_findings.map(f => `<div style="font-size: 13px; margin-bottom: 4px;">❌ ${f.title}</div>`).join('') || '<div style="font-size: 12px; color: var(--text-muted);">None</div>'}
            </div>
        </div>
    `;

    document.getElementById('close-diff-btn').onclick = () => {
        diffContainer.classList.add('hidden');
    };
}

// --- Settings & Gemini Key ---
function initSettings() {
    const keyInput = document.getElementById('gemini-key-input');
    const savedKey = localStorage.getItem('gemini_api_key');
    if (savedKey) {
        keyInput.value = savedKey;
        document.getElementById('ai-status-text').innerText = 'Gemini AI Active';
    }

    document.getElementById('save-settings-btn').addEventListener('click', () => {
        const key = keyInput.value.trim();
        if (key) {
            localStorage.setItem('gemini_api_key', key);
            document.getElementById('ai-status-text').innerText = 'Gemini AI Active';
            alert('Gemini API Key saved successfully!');
        } else {
            localStorage.removeItem('gemini_api_key');
            document.getElementById('ai-status-text').innerText = 'Local Synthesis Active';
            alert('API Key cleared. Scanner will use local heuristic synthesis.');
        }
    });
}

function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
