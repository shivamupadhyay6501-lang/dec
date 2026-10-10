// Security Intelligence & Executive Auditor Frontend Application Logic
let currentReport = null;
let activeSocket = null;
let currentFilter = 'ALL';
let currentAccount = null;
let currentHistoryFilter = 'all';

document.addEventListener('DOMContentLoaded', () => {
    initUserAccount();
    initNavigation();
    initScanForm();
    initChatInterface();
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

    document.getElementById('export-pdf-btn')?.addEventListener('click', () => {
        if (currentReport && currentReport.scan_id) {
            exportPDF(currentReport.scan_id);
        } else {
            alert('No active scan report loaded to export.');
        }
    });

    document.getElementById('export-html-btn')?.addEventListener('click', () => {
        if (currentReport && currentReport.scan_id) {
            exportHTML(currentReport.scan_id);
        } else {
            alert('No active scan report loaded to export.');
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
    } else if (tabId === 'chat') {
        populateChatScanSelect();
    } else if (tabId === 'dashboard') {
        if (!currentReport) {
            loadLatestScanToDashboard();
        }
    }
}

async function loadLatestScanToDashboard() {
    try {
        const resp = await fetch('/api/scans');
        const scans = await resp.json();
        if (scans && scans.length > 0) {
            const latestId = scans[0].id;
            const detailResp = await fetch(`/api/scans/${latestId}`);
            if (detailResp.ok) {
                const report = await detailResp.json();
                currentReport = report;
                renderExecutiveReport(report);
            }
        }
    } catch (err) {
        console.debug('Auto-load latest scan error:', err);
    }
}

// --- Scanner Input & Execution ---
let selectedEngine = localStorage.getItem('scan_engine') || 'local';

function initScanForm() {
    const toggleWeb = document.getElementById('toggle-web');
    const toggleUrl = document.getElementById('toggle-url');
    const toggleFile = document.getElementById('toggle-file');
    
    const webForm = document.getElementById('web-scan-form');
    const urlForm = document.getElementById('url-scan-form');
    const fileForm = document.getElementById('file-scan-form');
    
    const dropZone = document.getElementById('apk-drop-zone');
    const fileInput = document.getElementById('apk-file-input');

    const engineLocal = document.getElementById('engine-local');
    const engineCloud = document.getElementById('engine-cloud');

    // Restore engine selection
    const savedToken = localStorage.getItem('github_token');
    if (selectedEngine === 'github_cloud' && savedToken && engineCloud && engineLocal) {
        engineCloud.classList.add('active');
        engineLocal.classList.remove('active');
    } else {
        selectedEngine = 'local';
        engineLocal?.classList.add('active');
        engineCloud?.classList.remove('active');
    }

    engineLocal?.addEventListener('click', () => {
        selectedEngine = 'local';
        localStorage.setItem('scan_engine', 'local');
        engineLocal.classList.add('active');
        engineCloud?.classList.remove('active');
    });

    engineCloud?.addEventListener('click', () => {
        const token = localStorage.getItem('github_token');
        if (!token) {
            const goToSettings = confirm('☁️ GitHub Actions Cloud Runner executes audits on GitHub\'s free cloud servers (great for mobile/remote use).\n\nA GitHub Personal Access Token (PAT) is required.\n\nClick OK to open Settings and paste your token, or Cancel to keep using Local compute.');
            if (goToSettings) {
                switchTab('settings');
                return;
            } else {
                return;
            }
        }
        selectedEngine = 'github_cloud';
        localStorage.setItem('scan_engine', 'github_cloud');
        engineCloud.classList.add('active');
        engineLocal?.classList.remove('active');
    });

    // Toggle Handlers
    toggleWeb?.addEventListener('click', () => {
        toggleWeb.classList.add('active');
        toggleUrl?.classList.remove('active');
        toggleFile?.classList.remove('active');
        webForm?.classList.remove('hidden');
        urlForm?.classList.add('hidden');
        fileForm?.classList.add('hidden');
    });

    toggleUrl?.addEventListener('click', () => {
        toggleUrl.classList.add('active');
        toggleWeb?.classList.remove('active');
        toggleFile?.classList.remove('active');
        urlForm?.classList.remove('hidden');
        webForm?.classList.add('hidden');
        fileForm?.classList.add('hidden');
    });

    toggleFile?.addEventListener('click', () => {
        toggleFile.classList.add('active');
        toggleWeb?.classList.remove('active');
        toggleUrl?.classList.remove('active');
        fileForm?.classList.remove('hidden');
        webForm?.classList.add('hidden');
        urlForm?.classList.add('hidden');
    });

    // Quick sample links for Web
    document.querySelectorAll('.sample-web-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const urlInput = document.getElementById('web-url-input');
            if (urlInput) urlInput.value = link.getAttribute('data-url');
        });
    });

    // Quick sample links for Mobile
    document.querySelectorAll('.sample-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const pkgInput = document.getElementById('playstore-url-input');
            if (pkgInput) pkgInput.value = link.getAttribute('data-pkg');
        });
    });

    // Web Scan Trigger
    document.getElementById('start-web-scan-btn')?.addEventListener('click', () => {
        const inputVal = document.getElementById('web-url-input')?.value.trim();
        if (!inputVal) {
            alert('Please enter a website URL (e.g. https://example.com).');
            return;
        }
        startWebScan(inputVal);
    });

    // Mobile URL Scan Trigger
    document.getElementById('start-url-scan-btn')?.addEventListener('click', () => {
        const inputVal = document.getElementById('playstore-url-input')?.value.trim();
        if (!inputVal) {
            alert('Please enter a Google Play URL or Android package name.');
            return;
        }
        startUrlScan(inputVal);
    });

    // File Drop Zone
    if (dropZone && fileInput) {
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
    }

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
async function startWebScan(targetUrl) {
    targetUrl = (targetUrl || '').trim();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
        targetUrl = 'https://' + targetUrl;
    }
    const webInput = document.getElementById('web-url-input');
    if (webInput) webInput.value = targetUrl;

    const apiKey = localStorage.getItem('gemini_api_key') || '';
    const ghToken = localStorage.getItem('github_token') || '';

    if (selectedEngine === 'github_cloud' && !ghToken) {
        const runLocal = confirm('GitHub Personal Access Token is not set for Cloud Runner.\n\nClick OK to run this scan on your Local Machine instead,\nor Cancel to open Settings and enter your GitHub PAT.');
        if (runLocal) {
            selectedEngine = 'local';
            localStorage.setItem('scan_engine', 'local');
            document.getElementById('engine-local')?.classList.add('active');
            document.getElementById('engine-cloud')?.classList.remove('active');
        } else {
            switchTab('settings');
            return;
        }
    }

    showLiveTerminal();

    try {
        const engineLabel = selectedEngine === 'github_cloud' ? '☁️ GitHub Actions Cloud Runner' : '⚡ Local Machine';
        appendLogLine(`[INIT] Starting Web Security Audit on ${engineLabel} for ${targetUrl}...`, 'info');
        
        const accId = currentAccount?.account_id || null;
        const resp = await fetch('/api/scan/web', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: targetUrl,
                account_id: accId,
                gemini_api_key: apiKey,
                engine: selectedEngine,
                github_token: ghToken
            })
        });

        const data = await resp.json();
        if (data.scan_id) {
            connectScanWebSocket(data.scan_id);
            startScanPolling(data.scan_id);
        } else {
            throw new Error(data.detail || 'Failed to initialize scan');
        }
    } catch (err) {
        appendLogLine(`[ERROR] Failed to start web scan: ${err.message}`, 'error');
    }
}

async function startUrlScan(target) {
    target = (target || '').trim();

    // Check if user entered a website URL or bare web domain in the mobile input
    const isBareDomain = /^[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+(\/.*)?$/.test(target) && 
        !target.startsWith('com.') && !target.startsWith('org.') && !target.startsWith('net.') && !target.startsWith('io.') &&
        /\.(com|org|net|io|co|in|ai|app|dev|xyz|edu|gov|site|online|me|tv|cc)(\/|$)/i.test(target);
    const isFullWebUrl = target.startsWith('http://') || (target.startsWith('https://') && !target.includes('play.google.com'));

    if (isBareDomain || isFullWebUrl) {
        showLiveTerminal();
        appendLogLine(`[AUTO-DETECT] '${target}' recognized as a Website domain. Automatically routing to Web Security Auditor...`, 'info');
        return startWebScan(target);
    }

    const apiKey = localStorage.getItem('gemini_api_key') || '';
    const ghToken = localStorage.getItem('github_token') || '';

    if (selectedEngine === 'github_cloud' && !ghToken) {
        const runLocal = confirm('GitHub Personal Access Token is not set for Cloud Runner.\n\nClick OK to run this scan on your Local Machine instead,\nor Cancel to open Settings and enter your GitHub PAT.');
        if (runLocal) {
            selectedEngine = 'local';
            localStorage.setItem('scan_engine', 'local');
            document.getElementById('engine-local')?.classList.add('active');
            document.getElementById('engine-cloud')?.classList.remove('active');
        } else {
            switchTab('settings');
            return;
        }
    }

    showLiveTerminal();

    try {
        const engineLabel = selectedEngine === 'github_cloud' ? '☁️ GitHub Actions Cloud Runner' : '⚡ Local Machine';
        appendLogLine(`[INIT] Starting Mobile Security Audit on ${engineLabel}...`, 'info');
        
        const accId = currentAccount?.account_id || null;
        const resp = await fetch('/api/scan/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url_or_package: target,
                account_id: accId,
                gemini_api_key: apiKey,
                engine: selectedEngine,
                github_token: ghToken
            })
        });

        const data = await resp.json();
        if (data.scan_id) {
            connectScanWebSocket(data.scan_id);
            startScanPolling(data.scan_id);
        } else {
            throw new Error(data.detail || 'Failed to initialize scan');
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
    if (currentAccount?.account_id) formData.append('account_id', currentAccount.account_id);

    try {
        appendLogLine(`[UPLOAD] Uploading ${file.name} (${(file.size / (1024*1024)).toFixed(2)} MB)...`, 'info');
        const resp = await fetch('/api/scan/upload', {
            method: 'POST',
            body: formData
        });

        const data = await resp.json();
        if (data.scan_id) {
            connectScanWebSocket(data.scan_id);
            startScanPolling(data.scan_id);
        } else {
            throw new Error(data.detail || 'Upload failed');
        }
    } catch (err) {
        appendLogLine(`[ERROR] File upload failed: ${err.message}`, 'error');
    }
}

function showLiveTerminal() {
    const liveCard = document.getElementById('live-scan-card');
    liveCard?.classList.remove('hidden');
    const logs = document.getElementById('terminal-logs');
    if (logs) logs.innerHTML = '';
    const fill = document.getElementById('live-progress-fill');
    if (fill) fill.style.width = '5%';
    const pct = document.getElementById('live-scan-percent');
    if (pct) pct.innerText = '5%';
    const status = document.getElementById('live-scan-status');
    if (status) status.innerText = 'Initializing Pipeline...';
}

function renderTerminalActions(report) {
    const logs = document.getElementById('terminal-logs');
    if (!logs) return;
    if (document.getElementById('terminal-finish-actions')) return;
    
    const actionBox = document.createElement('div');
    actionBox.id = 'terminal-finish-actions';
    actionBox.style.cssText = 'margin-top: 15px; padding-top: 12px; border-top: 1px solid rgba(255,255,255,0.15); display: flex; gap: 10px; flex-wrap: wrap; align-items: center;';
    const scanId = report.scan_id || report.id || '';
    actionBox.innerHTML = `
        <button class="btn btn-primary btn-sm" onclick="switchTab('dashboard')">📊 Open Executive Dashboard Now</button>
        <button class="btn btn-secondary btn-sm" onclick="exportPDF('${scanId}')">📄 Export PDF</button>
        <button class="btn btn-secondary btn-sm" onclick="switchTab('history')">📜 View All Scans</button>
    `;
    logs.appendChild(actionBox);
    logs.scrollTop = logs.scrollHeight;
}

let scanPollInterval = null;

function startScanPolling(scanId) {
    if (scanPollInterval) clearInterval(scanPollInterval);

    let attempts = 0;
    scanPollInterval = setInterval(async () => {
        attempts++;
        try {
            const resp = await fetch(`/api/scans/${scanId}`);
            if (resp.status === 200) {
                const report = await resp.json();
                if (report && (report.scan_id === scanId || report.id === scanId)) {
                    clearInterval(scanPollInterval);
                    scanPollInterval = null;
                    if (activeSocket) {
                        try { activeSocket.close(); } catch(e) {}
                    }
                    const score = report?.score_data?.score ?? 'N/A';
                    const targetName = report?.app_info?.title || report?.app_info?.domain || report?.app_info?.package || 'Target';
                    
                    const fill = document.getElementById('live-progress-fill');
                    if (fill) fill.style.width = '100%';
                    const pct = document.getElementById('live-scan-percent');
                    if (pct) pct.innerText = '100%';
                    const status = document.getElementById('live-scan-status');
                    if (status) status.innerText = `Audit Finished! Security Score: ${score}/100`;

                    appendLogLine(`[COMPLETE] Security audit completed! ${targetName} Score: ${score}/100.`, 'success');
                    appendLogLine(`[READY] Opening Executive Dashboard...`, 'success');
                    
                    currentReport = report;
                    renderExecutiveReport(report);
                    loadAuditHistory();
                    renderTerminalActions(report);

                    setTimeout(() => {
                        switchTab('dashboard');
                    }, 2000);
                }
            }
        } catch (e) {
            console.debug('Polling scan status:', e);
        }

        if (attempts > 300) {
            clearInterval(scanPollInterval);
            scanPollInterval = null;
        }
    }, 2000);
}

function connectScanWebSocket(scanId) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/scan/${scanId}`;
    
    if (activeSocket) {
        try { activeSocket.close(); } catch(e) {}
    }
    activeSocket = new WebSocket(wsUrl);

    activeSocket.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'progress') {
                const fill = document.getElementById('live-progress-fill');
                if (fill) fill.style.width = `${msg.percent}%`;
                const pct = document.getElementById('live-scan-percent');
                if (pct) pct.innerText = `${msg.percent}%`;
                const status = document.getElementById('live-scan-status');
                if (status) status.innerText = msg.message;
                appendLogLine(`[${msg.percent}%] ${msg.message}`, 'info');
            } else if (msg.type === 'complete') {
                if (scanPollInterval) {
                    clearInterval(scanPollInterval);
                    scanPollInterval = null;
                }
                const score = msg.report?.score_data?.score ?? 'N/A';
                const targetName = msg.report?.app_info?.title || msg.report?.app_info?.domain || msg.report?.app_info?.package || 'Target';
                
                const fill = document.getElementById('live-progress-fill');
                if (fill) fill.style.width = '100%';
                const pct = document.getElementById('live-scan-percent');
                if (pct) pct.innerText = '100%';
                const status = document.getElementById('live-scan-status');
                if (status) status.innerText = `Audit Finished! Security Score: ${score}/100`;

                appendLogLine(`[COMPLETE] Security audit completed! ${targetName} Score: ${score}/100.`, 'success');
                appendLogLine(`[READY] Opening Executive Dashboard...`, 'success');
                
                currentReport = msg.report;
                renderExecutiveReport(msg.report);
                loadAuditHistory();
                renderTerminalActions(msg.report);

                setTimeout(() => {
                    switchTab('dashboard');
                }, 2000);
            } else if (msg.type === 'error') {
                appendLogLine(`[FATAL ERROR] ${msg.error}`, 'error');
            }
        } catch (parseErr) {
            console.error('WebSocket parse error:', parseErr);
        }
    };

    activeSocket.onerror = () => {
        console.debug('WebSocket connection error - background polling active.');
    };
}

function appendLogLine(text, type = 'info') {
    const logs = document.getElementById('terminal-logs');
    if (!logs) return;
    const line = document.createElement('div');
    line.className = `log-line ${type}`;
    line.innerText = text;
    logs.appendChild(line);
    logs.scrollTop = logs.scrollHeight;
}

// --- Render Executive Report ---
function renderExecutiveReport(report) {
    if (!report) return;
    currentReport = report;

    try {
        const app = report.app_info || {};
        const tech = report.tech_info || {};
        const scoreData = report.score_data || {};
        const counts = scoreData.counts || {};
        const isWeb = Boolean(app.is_web || (report.scan_id && report.scan_id.includes('WEB')));

        // Header metadata
        const titleElem = document.getElementById('report-app-title');
        if (titleElem) titleElem.innerText = app.title || app.domain || app.package || 'Security Audit';

        const typeBadge = document.getElementById('report-type-badge');
        if (typeBadge) typeBadge.innerText = isWeb ? '🌐 Web Target' : '📱 Mobile APK';

        const pkgElem = document.getElementById('report-package');
        if (pkgElem) pkgElem.innerText = app.domain || app.package || 'N/A';

        const verElem = document.getElementById('report-version');
        if (verElem) verElem.innerText = isWeb ? (app.version_name || 'HTTP 200') : `v${app.version_name || '1.0'}`;

        const fwElem = document.getElementById('report-framework');
        if (fwElem) fwElem.innerText = tech.primary_framework || (isWeb ? 'Web Application' : 'Native Android');

        const sdkElem = document.getElementById('report-sdk');
        if (sdkElem) sdkElem.innerText = isWeb ? (tech.server || app.target_sdk || 'HTTPS/TLS') : `Target SDK ${app.target_sdk || 'N/A'}`;

        const iconElem = document.getElementById('report-app-icon');
        if (iconElem) {
            if (app.icon_url) {
                iconElem.innerHTML = `<img src="${app.icon_url}" style="width:100%;height:100%;border-radius:14px;object-fit:cover;" onerror="this.parentElement.innerHTML='${isWeb ? '🌐' : '📱'}'">`;
            } else {
                iconElem.innerHTML = isWeb ? '🌐' : '📱';
            }
        }

        // Score Dial & Counters
        const score = typeof scoreData.score === 'number' ? scoreData.score : 0;
        const scoreNum = document.getElementById('report-score-num');
        if (scoreNum) scoreNum.innerText = score;

        const riskLevel = document.getElementById('report-risk-level');
        if (riskLevel) riskLevel.innerText = scoreData.rating || scoreData.risk_level || 'AUDITED';

        // SVG circle offset calculation (circumference = 2 * PI * 50 = 314.15)
        const meter = document.getElementById('score-meter');
        if (meter) {
            const offset = 314 - (score / 100) * 314;
            meter.style.strokeDashoffset = offset;
            const scoreColor = score < 50 ? 'var(--sev-critical)' : score < 75 ? 'var(--sev-high)' : 'var(--sev-low)';
            meter.style.stroke = scoreColor;
        }

        const cCrit = document.getElementById('count-critical');
        if (cCrit) cCrit.innerText = counts.CRITICAL || 0;

        const cHigh = document.getElementById('count-high');
        if (cHigh) cHigh.innerText = counts.HIGH || 0;

        const cMed = document.getElementById('count-medium');
        if (cMed) cMed.innerText = counts.MEDIUM || 0;

        const cLow = document.getElementById('count-low');
        if (cLow) cLow.innerText = (counts.LOW || 0) + (counts.INFO || 0);

        // AI Briefing
        const summaryElem = document.getElementById('report-executive-summary');
        if (summaryElem) summaryElem.innerText = report.executive_summary || 'No summary available.';

        const aiBadge = document.getElementById('report-ai-badge');
        if (aiBadge) aiBadge.innerText = report.ai_engine || 'Gemini 2.5 Flash';

        // Top Priorities ("Fix These First")
        const prioritiesContainer = document.getElementById('priorities-container');
        if (prioritiesContainer) {
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
                            <span>#${p.priority || idx + 1} — ${escapeHtml(p.title || 'Security Issue')}</span>
                            <span class="badge-pill ${(p.severity || 'critical').toLowerCase()}">${p.severity || 'CRITICAL'}</span>
                        </div>
                        <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">
                            <strong>Potential Impact:</strong> ${escapeHtml(p.potential_impact || 'High exposure.')}
                        </div>
                        <div style="font-size: 13px; color: #34d399; margin-top: 4px;">
                            <strong>Action Required:</strong> ${escapeHtml(p.action_required || 'Remediate in code.')}
                        </div>
                    `;
                    prioritiesContainer.appendChild(item);
                });
            }
        }

        // Cloud & Firebase Diagnostics
        const cloudCard = document.getElementById('cloud-diag-card');
        const cloudContainer = document.getElementById('cloud-diag-container');
        const cloudBadge = document.getElementById('cloud-diag-badge');
        if (cloudCard && cloudContainer) {
            const diags = report.cloud_diagnostics || [];
            if (diags.length > 0) {
                cloudCard.classList.remove('hidden');
                if (cloudBadge) cloudBadge.innerText = `${diags.length} Endpoints Tested`;
                cloudContainer.innerHTML = '';
                diags.forEach(d => {
                    const item = document.createElement('div');
                    item.className = 'cloud-diag-item';
                    const isVuln = d.verdict === 'VULNERABLE';
                    const isSec = d.verdict === 'SECURE';
                    const badgeClass = isVuln ? 'critical' : (isSec ? 'low' : 'info');
                    item.innerHTML = `
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                            <div>
                                <strong>${escapeHtml(d.service || 'Cloud Storage')}</strong> &bull; <code>${escapeHtml(d.target_url || '')}</code>
                            </div>
                            <span class="badge-pill ${badgeClass}">${escapeHtml(d.verdict_badge || d.verdict || 'AUDITED')}</span>
                        </div>
                        <div style="font-size: 13px; color: var(--text-muted);">${escapeHtml(d.details || '')}</div>
                    `;
                    cloudContainer.appendChild(item);
                });
            } else {
                cloudCard.classList.add('hidden');
            }
        }

        // Render findings list
        renderFindingsList();
    } catch (renderErr) {
        console.error('Error in renderExecutiveReport:', renderErr);
    }
}

function renderFindingsList() {
    const container = document.getElementById('findings-container');
    if (!container) return;
    container.innerHTML = '';

    if (!currentReport || !currentReport.findings) return;

    let findings = currentReport.findings;
    if (currentFilter !== 'ALL') {
        findings = findings.filter(f => (f.severity || '').toUpperCase() === currentFilter);
    }

    const totalCountElem = document.getElementById('findings-total-count');
    if (totalCountElem) totalCountElem.innerText = currentReport.findings.length;

    if (findings.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 20px;">No findings matching current filter.</div>';
        return;
    }

    findings.forEach(f => {
        const card = document.createElement('div');
        card.className = 'finding-card-item';

        const ev = f.evidence || {};
        const codeSnippet = ev.context_snippet ? `<pre class="code-viewer"><code>${escapeHtml(ev.context_snippet)}</code></pre>` : '';
        const loc = ev.file ? `${ev.file}${ev.line ? ':' + ev.line : ''}` : 'Target Configuration';

        card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h3 style="font-size: 16px; font-weight: 700;">${escapeHtml(f.title || 'Security Finding')}</h3>
                <span class="badge-pill ${(f.severity || 'info').toLowerCase()}">${f.severity || 'INFO'}</span>
            </div>
            <div class="finding-meta" style="margin: 6px 0;">
                <span>📁 Category: <strong>${escapeHtml(f.category || 'General')}</strong></span> &bull; 
                <span>📍 Location: <code>${escapeHtml(loc)}</code></span>
            </div>
            <p style="color: #cbd5e1; font-size: 14px; margin-bottom: 8px;">${escapeHtml(f.impact || '')}</p>
            ${codeSnippet}
            <div class="remediation-box">
                <strong>💡 Remediation:</strong> ${escapeHtml(f.remediation || 'Follow secure coding practices.')}
            </div>
        `;
        container.appendChild(card);
    });
}

// --- User Account Onboarding & Management ---
function initUserAccount() {
    // Bind click & key listeners directly
    document.getElementById('onboarding-submit-btn')?.addEventListener('click', submitOnboarding);
    document.getElementById('onboarding-name-input')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            submitOnboarding();
        }
    });
    document.getElementById('sidebar-user-badge')?.addEventListener('click', openProfileModal);

    const saved = localStorage.getItem('audit_user_account');
    if (!saved) {
        generateNewAccountId();
        const modal = document.getElementById('onboarding-modal');
        if (modal) {
            modal.classList.remove('hidden');
            modal.style.display = 'flex';
        }
    } else {
        try {
            currentAccount = JSON.parse(saved);
            updateUserBadgeUI();
        } catch (e) {
            generateNewAccountId();
            const modal = document.getElementById('onboarding-modal');
            if (modal) {
                modal.classList.remove('hidden');
                modal.style.display = 'flex';
            }
        }
    }
}

function generateNewAccountId() {
    const randomAcc = 'ACC-' + Math.floor(100000 + Math.random() * 900000);
    const accElem = document.getElementById('onboarding-account-id');
    if (accElem) accElem.innerText = randomAcc;
    return randomAcc;
}

function generateNewProfileAccountId() {
    const randomAcc = 'ACC-' + Math.floor(100000 + Math.random() * 900000);
    const input = document.getElementById('profile-account-input');
    if (input) input.value = randomAcc;
}

async function submitOnboarding() {
    const nameInput = document.getElementById('onboarding-name-input');
    const name = nameInput?.value.trim() || 'Security Researcher';
    const accountId = document.getElementById('onboarding-account-id')?.innerText.trim() || generateNewAccountId();

    currentAccount = { name: name, account_id: accountId, created_at: new Date().toISOString() };
    localStorage.setItem('audit_user_account', JSON.stringify(currentAccount));

    updateUserBadgeUI();
    const modal = document.getElementById('onboarding-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.style.display = 'none';
    }

    try {
        await fetch('/api/user/account', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: name, account_id: accountId })
        });
    } catch (err) {
        console.debug('Account register sync:', err);
    }
    loadAuditHistory();
}

function closeOnboardingModal() {
    const modal = document.getElementById('onboarding-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.style.display = 'none';
    }
    if (!currentAccount) {
        const accountId = generateNewAccountId();
        currentAccount = { name: 'Security Researcher', account_id: accountId, created_at: new Date().toISOString() };
        localStorage.setItem('audit_user_account', JSON.stringify(currentAccount));
        updateUserBadgeUI();
    }
}

function updateUserBadgeUI() {
    if (!currentAccount) return;
    const nameElem = document.getElementById('sidebar-user-name');
    const accElem = document.getElementById('sidebar-user-acc');
    const filterAccElem = document.getElementById('filter-user-acc');
    if (nameElem) nameElem.innerText = currentAccount.name || 'Auditor';
    if (accElem) accElem.innerText = currentAccount.account_id || 'ACC-000000';
    if (filterAccElem) filterAccElem.innerText = currentAccount.account_id || 'ACC-000000';
}

function openProfileModal() {
    const nameInput = document.getElementById('profile-name-input');
    const accInput = document.getElementById('profile-account-input');
    if (nameInput) nameInput.value = currentAccount?.name || '';
    if (accInput) accInput.value = currentAccount?.account_id || generateNewProfileAccountId();
    const modal = document.getElementById('profile-modal');
    if (modal) {
        modal.classList.remove('hidden');
        modal.style.display = 'flex';
    }
}

function closeProfileModal() {
    const modal = document.getElementById('profile-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.style.display = 'none';
    }
}

async function saveProfileChanges() {
    const name = document.getElementById('profile-name-input')?.value.trim() || 'Security Researcher';
    const accountId = document.getElementById('profile-account-input')?.value.trim() || (currentAccount?.account_id || generateNewAccountId());

    currentAccount = { ...currentAccount, name: name, account_id: accountId };
    localStorage.setItem('audit_user_account', JSON.stringify(currentAccount));
    updateUserBadgeUI();
    closeProfileModal();

    try {
        await fetch('/api/user/account', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: name, account_id: accountId })
        });
        loadAuditHistory();
    } catch (e) {
        console.debug('Save profile err:', e);
    }
}

// --- Audit History & Cloudflare R2 Sync ---
function setHistoryFilter(filter) {
    currentHistoryFilter = filter;
    document.getElementById('history-filter-all')?.classList.toggle('active', filter === 'all');
    document.getElementById('history-filter-mine')?.classList.toggle('active', filter === 'mine');
    loadAuditHistory();
}

async function syncR2Storage() {
    const pill = document.getElementById('r2-status-pill');
    const btn = document.getElementById('sync-r2-btn');
    const originalText = btn ? btn.innerText : '';
    if (btn) {
        btn.disabled = true;
        btn.innerText = '⏳ Syncing R2...';
    }
    if (pill) pill.innerText = '🔄 Syncing Cloudflare R2...';

    try {
        const resp = await fetch('/api/storage/sync', { method: 'POST' });
        const data = await resp.json();
        if (data.status === 'success') {
            if (pill) pill.innerText = `☁️ R2 Synced (+${data.synced_to_local} imported, +${data.pushed_to_remote} uploaded)`;
            loadAuditHistory();
        } else {
            if (pill) pill.innerText = '⚠️ R2 Sync Issue';
        }
    } catch (err) {
        if (pill) pill.innerText = '❌ R2 Sync Error';
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerText = originalText || '☁️ Sync Cloudflare R2';
        }
    }
}

async function loadAuditHistory() {
    try {
        let url = '/api/scans';
        if (currentHistoryFilter === 'mine' && currentAccount && currentAccount.account_id) {
            url += `?account_id=${encodeURIComponent(currentAccount.account_id)}`;
        }
        const resp = await fetch(url);
        const scans = await resp.json();
        const tbody = document.getElementById('history-tbody');
        if (!tbody) return;
        tbody.innerHTML = '';

        if (!scans || scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 30px;">No scans recorded yet. Run a new audit or click <strong>☁️ Sync Cloudflare R2</strong> to pull past reports.</td></tr>';
            return;
        }

        scans.forEach(s => {
            const isWeb = (s.framework && s.framework.toLowerCase().includes('web')) || (s.id && s.id.includes('WEB'));
            const isMyScan = currentAccount && s.account_id === currentAccount.account_id;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><code>${escapeHtml(s.id)}</code></td>
                <td><span class="tag" style="color: ${isMyScan ? '#38bdf8' : 'var(--text-muted)'}">${escapeHtml(s.account_id || 'System')}</span></td>
                <td><strong>${escapeHtml(s.app_title || s.package_name)}</strong></td>
                <td><span class="badge-pill ${isWeb ? 'low' : 'info'}">${isWeb ? '🌐 Web' : '📱 APK'}</span></td>
                <td><span class="tag">${escapeHtml(s.version_name || '1.0')}</span></td>
                <td><strong style="color: ${s.security_score < 50 ? 'var(--sev-critical)' : 'var(--sev-low)'}">${s.security_score}/100</strong></td>
                <td><span class="badge-pill critical">${s.critical_count}</span></td>
                <td><span class="badge-pill high">${s.high_count}</span></td>
                <td style="color: var(--text-muted); font-size: 12px;">${new Date(s.created_at).toLocaleDateString()}</td>
                <td style="display: flex; gap: 6px; flex-wrap: wrap;">
                    <button class="btn btn-secondary btn-sm" onclick="loadScanDetails('${s.id}')">View</button>
                    <button class="btn btn-secondary btn-sm" onclick="exportPDF('${s.id}')">PDF</button>
                    ${scans.length > 1 ? `<button class="btn btn-secondary btn-sm" onclick="compareWithLatest('${s.id}')">Diff</button>` : ''}
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error('Failed to load history:', err);
    }
}

async function syncCloudRuns() {
    const btn = document.getElementById('sync-cloud-runs-btn');
    const originalText = btn ? btn.innerText : '';
    if (btn) {
        btn.innerText = '⏳ Syncing GitHub...';
        btn.disabled = true;
    }

    const token = localStorage.getItem('github_token') || '';
    try {
        const resp = await fetch('/api/cloud/sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ github_token: token })
        });
        const data = await resp.json();
        if (data.status === 'success') {
            alert(`✅ Cloud Sync Complete! Successfully imported ${data.synced_count} workflow audit reports from GitHub Actions.`);
            loadAuditHistory();
        } else {
            alert(`⚠️ Cloud Sync Notice: ${data.message || 'Could not fetch runs'}`);
        }
    } catch (err) {
        alert(`Failed to sync from GitHub Actions: ${err.message}`);
    } finally {
        if (btn) {
            btn.innerText = originalText;
            btn.disabled = false;
        }
    }
}

async function loadScanDetails(scanId) {
    try {
        const resp = await fetch(`/api/scans/${scanId}`);
        if (!resp.ok) throw new Error(`HTTP Error ${resp.status}`);
        const report = await resp.json();
        currentReport = report;
        renderExecutiveReport(report);
        switchTab('dashboard');
    } catch (err) {
        alert('Failed to load scan: ' + err.message);
    }
}

function exportPDF(scanId) {
    window.open(`/api/export/${scanId}/pdf?print=true`, '_blank');
}

function exportHTML(scanId) {
    window.open(`/api/export/${scanId}/html`, '_blank');
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
    if (!diffContainer) return;
    diffContainer.classList.remove('hidden');

    const scoreChange = diff.score_diff >= 0 ? `+${diff.score_diff}` : `${diff.score_diff}`;
    const scoreColor = diff.score_diff >= 0 ? '#10b981' : '#ef4444';

    const diffBody = document.getElementById('diff-body');
    if (diffBody) {
        diffBody.innerHTML = `
            <div style="display: flex; justify-content: space-around; background: #090d16; padding: 18px; border-radius: 8px; margin-bottom: 20px;">
                <div style="text-align: center;">
                    <div style="font-size: 12px; color: var(--text-muted);">Base Version (${escapeHtml(diff.base_version.version_name)})</div>
                    <div style="font-size: 22px; font-weight: 800;">${diff.base_version.score}/100</div>
                </div>
                <div style="text-align: center;">
                    <div style="font-size: 12px; color: var(--text-muted);">Score Progression</div>
                    <div style="font-size: 22px; font-weight: 800; color: ${scoreColor};">${scoreChange} pts</div>
                </div>
                <div style="text-align: center;">
                    <div style="font-size: 12px; color: var(--text-muted);">New Version (${escapeHtml(diff.new_version.version_name)})</div>
                    <div style="font-size: 22px; font-weight: 800;">${diff.new_version.score}/100</div>
                </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                <div style="background: rgba(16, 185, 129, 0.06); border: 1px solid rgba(16, 185, 129, 0.2); padding: 16px; border-radius: 8px;">
                    <h4 style="color: #34d399; margin-bottom: 8px;">🎉 Resolved Vulnerabilities (${diff.resolved_count})</h4>
                    ${diff.resolved_findings.map(f => `<div style="font-size: 13px; margin-bottom: 4px;">✅ ${escapeHtml(f.title)}</div>`).join('') || '<div style="font-size: 12px; color: var(--text-muted);">None</div>'}
                </div>

                <div style="background: rgba(239, 68, 68, 0.06); border: 1px solid rgba(239, 68, 68, 0.2); padding: 16px; border-radius: 8px;">
                    <h4 style="color: #f87171; margin-bottom: 8px;">⚠️ New Vulnerabilities Introduced (${diff.introduced_count})</h4>
                    ${diff.introduced_findings.map(f => `<div style="font-size: 13px; margin-bottom: 4px;">❌ ${escapeHtml(f.title)}</div>`).join('') || '<div style="font-size: 12px; color: var(--text-muted);">None</div>'}
                </div>
            </div>
        `;
    }

    const closeBtn = document.getElementById('close-diff-btn');
    if (closeBtn) {
        closeBtn.onclick = () => {
            diffContainer.classList.add('hidden');
        };
    }
}

// --- Settings & Gemini Key ---
function initSettings() {
    const keyInput = document.getElementById('gemini-key-input');
    const ghTokenInput = document.getElementById('github-token-input');
    
    const savedKey = localStorage.getItem('gemini_api_key');
    if (savedKey && keyInput) {
        keyInput.value = savedKey;
        const statusText = document.getElementById('ai-status-text');
        if (statusText) statusText.innerText = 'Gemini AI Active';
    }

    const savedGhToken = localStorage.getItem('github_token');
    if (savedGhToken && ghTokenInput) {
        ghTokenInput.value = savedGhToken;
    }

    document.getElementById('save-settings-btn')?.addEventListener('click', () => {
        const key = keyInput?.value.trim();
        const ghToken = ghTokenInput?.value.trim();
        const statusText = document.getElementById('ai-status-text');
        
        if (key) {
            localStorage.setItem('gemini_api_key', key);
            if (statusText) statusText.innerText = 'Gemini AI Active';
        } else {
            localStorage.removeItem('gemini_api_key');
            if (statusText) statusText.innerText = 'Local Synthesis Active';
        }

        if (ghToken) {
            localStorage.setItem('github_token', ghToken);
        } else {
            localStorage.removeItem('github_token');
        }

        alert('Settings saved successfully!');
    });
}

// --- Interactive Code Chat Assistant ---
function initChatInterface() {
    const sendBtn = document.getElementById('chat-send-btn');
    const inputArea = document.getElementById('chat-user-input');
    const scanSelect = document.getElementById('chat-scan-select');

    // Quick prompt chips
    document.querySelectorAll('#chat-quick-prompts .prompt-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            const prompt = chip.getAttribute('data-prompt');
            if (inputArea) {
                inputArea.value = prompt;
                sendChatMessage();
            }
        });
    });

    sendBtn?.addEventListener('click', () => {
        sendChatMessage();
    });

    inputArea?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendChatMessage();
        }
    });

    scanSelect?.addEventListener('change', () => {
        const scanId = scanSelect.value;
        if (scanId) {
            updateChatPrompts(scanId);
        }
    });
}

async function populateChatScanSelect() {
    const scanSelect = document.getElementById('chat-scan-select');
    if (!scanSelect) return;

    try {
        const resp = await fetch('/api/scans');
        const scans = await resp.json();
        
        const currentValue = scanSelect.value;
        scanSelect.innerHTML = '<option value="">-- Select an audited app --</option>';

        if (scans && scans.length > 0) {
            scans.forEach(s => {
                const opt = document.createElement('option');
                opt.value = s.id;
                opt.innerText = `${s.app_title || s.package_name} (${s.id})`;
                scanSelect.appendChild(opt);
            });

            // If currentReport exists, select it
            if (currentReport && currentReport.scan_id) {
                scanSelect.value = currentReport.scan_id;
            } else if (currentValue && scans.some(s => s.id === currentValue)) {
                scanSelect.value = currentValue;
            } else if (scans.length > 0) {
                scanSelect.value = scans[0].id;
            }
        }
    } catch (err) {
        console.error('Failed to populate chat scan select:', err);
    }
}

async function updateChatPrompts(scanId) {
    try {
        const resp = await fetch(`/api/chat/prompts/${scanId}`);
        const data = await resp.json();
        const container = document.getElementById('chat-quick-prompts');
        if (container && data.prompts && data.prompts.length > 0) {
            container.innerHTML = '';
            data.prompts.forEach(p => {
                const chip = document.createElement('span');
                chip.className = 'prompt-chip';
                chip.setAttribute('data-prompt', p);
                chip.innerText = p;
                chip.addEventListener('click', () => {
                    const inputArea = document.getElementById('chat-user-input');
                    if (inputArea) {
                        inputArea.value = p;
                        sendChatMessage();
                    }
                });
                container.appendChild(chip);
            });
        }
    } catch (err) {
        console.debug('Failed to update chat prompts:', err);
    }
}

async function sendChatMessage() {
    const inputArea = document.getElementById('chat-user-input');
    const scanSelect = document.getElementById('chat-scan-select');
    const timeline = document.getElementById('chat-messages-timeline');

    const query = inputArea?.value.trim();
    if (!query) return;

    const scanId = scanSelect?.value || (currentReport ? currentReport.scan_id : null);
    if (!scanId) {
        alert('Please select an audited target app from the dropdown before chatting.');
        return;
    }

    // 1. Append User Message
    appendChatMessage('user', query);
    inputArea.value = '';

    // 2. Append Loading Placeholder
    const loadingId = 'loading-' + Date.now();
    const loadingElem = document.createElement('div');
    loadingElem.className = 'chat-msg ai-msg';
    loadingElem.id = loadingId;
    loadingElem.innerHTML = `
        <div class="msg-avatar">🤖</div>
        <div class="msg-content">
            <div class="typing-indicator">
                <span></span><span></span><span></span>
            </div>
            <small style="color: var(--text-muted); display: block; margin-top: 6px;">Deep-searching decompiled classes & synthesizing answer...</small>
        </div>
    `;
    timeline.appendChild(loadingElem);
    timeline.scrollTop = timeline.scrollHeight;

    const apiKey = localStorage.getItem('gemini_api_key') || '';

    try {
        const resp = await fetch('/api/chat/app', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                scan_id: scanId,
                query: query,
                gemini_api_key: apiKey
            })
        });

        const data = await resp.json();
        loadingElem.remove();

        appendChatMessage('ai', data.answer, data.snippets);
    } catch (err) {
        loadingElem.remove();
        appendChatMessage('ai', `⚠️ Error fetching response: ${err.message}`);
    }
}

function appendChatMessage(sender, text, snippets = []) {
    const timeline = document.getElementById('chat-messages-timeline');
    if (!timeline) return;

    const msg = document.createElement('div');
    msg.className = `chat-msg ${sender}-msg`;

    const avatar = sender === 'user' ? '👤' : '🤖';
    const formattedHtml = formatChatMarkdown(text);

    msg.innerHTML = `
        <div class="msg-avatar">${avatar}</div>
        <div class="msg-content">
            ${formattedHtml}
        </div>
    `;

    timeline.appendChild(msg);
    timeline.scrollTop = timeline.scrollHeight;
}

function formatChatMarkdown(text) {
    if (!text) return '';
    let html = escapeHtml(text);

    // Code blocks with triple backticks ```java ... ```
    html = html.replace(/```([a-zA-Z0-9_\-]+)?\n([\s\S]*?)```/g, (match, lang, code) => {
        return `<pre class="code-viewer"><div class="code-lang-tag">${lang || 'code'}</div><code>${code.trim()}</code></pre>`;
    });

    // Inline code `code`
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Bold **text**
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

    // Headers ###, ####
    html = html.replace(/^#### (.*$)/gim, '<h4 style="margin: 10px 0 4px 0; color: #38bdf8;">$1</h4>');
    html = html.replace(/^### (.*$)/gim, '<h3 style="margin: 12px 0 6px 0; color: #818cf8;">$1</h3>');

    // Bullet points - list item
    html = html.replace(/^\- (.*$)/gim, '<li style="margin-left: 18px; margin-bottom: 4px;">$1</li>');

    // Line breaks
    html = html.replace(/\n\n/g, '<br><br>').replace(/\n/g, '<br>');

    return html;
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

// Attach globally for inline HTML handlers
window.loadScanDetails = loadScanDetails;
window.compareWithLatest = compareWithLatest;
window.switchTab = switchTab;
window.exportPDF = exportPDF;
window.exportHTML = exportHTML;
window.loadAuditHistory = loadAuditHistory;
window.sendChatMessage = sendChatMessage;
window.syncCloudRuns = syncCloudRuns;
window.generateNewAccountId = generateNewAccountId;
window.generateNewProfileAccountId = generateNewProfileAccountId;
window.submitOnboarding = submitOnboarding;
window.closeOnboardingModal = closeOnboardingModal;
window.openProfileModal = openProfileModal;
window.closeProfileModal = closeProfileModal;
window.saveProfileChanges = saveProfileChanges;
window.setHistoryFilter = setHistoryFilter;
window.syncR2Storage = syncR2Storage;

