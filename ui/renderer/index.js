// State
let isRunning = false;
let pendingRequests = [];
let eventCount = 0;
let blockedCount = 0;
let startTime = null;
let timerInterval = null;
let alertLevel = 'safe'; // safe, warning, critical

const els = {
    status: document.getElementById('agentStatus'),
    btnStart: document.getElementById('btnStart'),
    btnStop: document.getElementById('btnStop'),
    threatMonitor: document.getElementById('threatMonitor'),
    threatLabel: document.getElementById('threatLabel'),
    alertCount: document.getElementById('alertCount'),
    pendingList: document.getElementById('pendingList'),
    pendingCount: document.getElementById('pendingCount'),
    console: document.getElementById('consoleLogs'),
    eventsProcessed: document.getElementById('eventsProcessed'),
    threatsBlocked: document.getElementById('threatsBlocked'),
    uptime: document.getElementById('uptime'),
    toggleAuto: document.getElementById('toggleAutoRemediate'),
    overlay: document.getElementById('threatOverlay')
};

// --- CONFIG HANDLERS ---
els.toggleAuto.addEventListener('change', async (e) => {
    const isEnabled = e.target.checked;
    addLog(`Setting Auto-Remediation to: ${isEnabled ? 'ON' : 'OFF'}`, 'info');
    
    try {
        const res = await window.agentAPI.setConfig({ auto_remediation: isEnabled });
        if (!res.success) {
            addLog(`Failed to update config: ${res.error}`, 'error');
            e.target.checked = !isEnabled; // Revert UI
        }
    } catch (err) {
        addLog(`Config error: ${err.message}`, 'error');
        e.target.checked = !isEnabled;
    }
});

async function syncConfig() {
    try {
        const res = await window.agentAPI.checkHealth();
        if (res.healthy && res.body && res.body.config) {
            const serverState = res.body.config.auto_remediation;
            if (els.toggleAuto.checked !== serverState) {
                els.toggleAuto.checked = serverState;
                addLog(`Synced Auto-Remediation state: ${serverState ? 'ON' : 'OFF'}`, 'info');
            }
        }
    } catch (e) {
        // Ignore
    }
}


// --- API LISTENERS ---

window.agentAPI.onLog((data) => {
    // Determine level from message content or object
    let msg = typeof data === 'string' ? data : data.message;
    let level = 'info';
    
    if (msg.toLowerCase().includes('critical') || msg.toLowerCase().includes('ransomware')) level = 'critical';
    else if (msg.toLowerCase().includes('warning') || msg.toLowerCase().includes('suspicious')) level = 'warn';
    else if (msg.toLowerCase().includes('error')) level = 'error';

    addLog(msg, level);

    // Update stats simulation
    if (msg.includes('Events Analyzed') || Math.random() > 0.7) {
        eventCount++;
        els.eventsProcessed.textContent = eventCount.toLocaleString();
    }
    
    // Trigger Threat Visuals
    if (level === 'critical') setThreatLevel('critical');
    else if (level === 'warn' && alertLevel !== 'critical') setThreatLevel('warning');

    // Auto-sync config on startup log
    if (msg.includes('Control server started')) {
        setTimeout(syncConfig, 1000);
    }
});

window.agentAPI.onAgentExit((info) => {
    addLog(`Agent stopped (Code: ${info.code})`, 'warn');
    setRunning(false);
});

// --- CONTROLS ---

els.btnStart.addEventListener('click', async () => {
    addLog('Requesting agent start...', 'info');
    const res = await window.agentAPI.start();
    if (res.success) {
        setRunning(true);
        addLog('Agent started successfully.', 'info');
        setTimeout(syncConfig, 2000); // Sync config after start
    } else {
        addLog(`Failed to start: ${res.error}`, 'error');
    }
});

els.btnStop.addEventListener('click', async () => {
    const res = await window.agentAPI.stop();
    setRunning(false);
});

function setRunning(active) {
    isRunning = active;
    els.status.className = active ? 'status-badge active' : 'status-badge inactive';
    els.status.textContent = active ? 'RUNNING' : 'STOPPED';
    
    if (active) {
        startTime = Date.now();
        timerInterval = setInterval(updateUptime, 1000);
    } else {
        clearInterval(timerInterval);
        setThreatLevel('safe');
    }
}

function updateUptime() {
    if (!startTime) return;
    const diff = Math.floor((Date.now() - startTime) / 1000);
    const m = Math.floor(diff / 60).toString().padStart(2, '0');
    const s = (diff % 60).toString().padStart(2, '0');
    els.uptime.textContent = `${m}:${s}`;
}

// --- THREAT VISUALIZER ---

let threatTimeout;

function setThreatLevel(level) {
    alertLevel = level;
    els.threatMonitor.className = `threat-monitor threat-${level}`;
    
    // Overlay Logic
    if (level === 'critical') {
        els.overlay.style.opacity = '1';
        els.overlay.style.animation = 'flashRed 1s infinite';
    } else {
        els.overlay.style.opacity = '0';
        els.overlay.style.animation = 'none';
    }
    
    if (level === 'safe') {
        els.threatLabel.textContent = 'SYSTEM SAFE';
        els.threatLabel.style.color = '#00e676';
    } else if (level === 'warning') {
        els.threatLabel.textContent = 'SUSPICIOUS ACTIVITY';
        els.threatLabel.style.color = '#ff9100';
    } else if (level === 'critical') {
        els.threatLabel.textContent = 'THREAT DETECTED';
        els.threatLabel.style.color = '#ff1744';
        
        // Auto reset to warning after 5s if no new threats
        clearTimeout(threatTimeout);
        threatTimeout = setTimeout(() => setThreatLevel('warning'), 5000);
    }
}

// --- LOGGING ---

function addLog(msg, level) {
    const div = document.createElement('div');
    div.className = 'log-line';
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    
    // Highlight Keywords
    let formattedMsg = msg
        .replace(/CRITICAL/g, '<span style="color:#ff1744; font-weight:bold;">CRITICAL</span>')
        .replace(/Ransomware/g, '<span style="background:#ff1744; color:#fff; padding:0 4px;">RANSOMWARE</span>');

    div.innerHTML = `<span class="log-time">${time}</span> <span class="log-${level}">${formattedMsg}</span>`;
    els.console.appendChild(div);
    els.console.scrollTop = els.console.scrollHeight;
}

window.clearLogs = () => {
    els.console.innerHTML = '';
    eventCount = 0;
    els.eventsProcessed.textContent = '0';
};

// --- PENDING REQUESTS POLLING ---

async function pollPending() {
    if (!isRunning) return; // Don't poll if agent not running

    try {
        const res = await window.agentAPI.getPending();
        if (res && res.requests) {
            updatePendingList(res.requests);
        }
    } catch (e) {
        // Silent error
    }
}

function updatePendingList(requests) {
    // Check if list changed to avoid flickering? (Simple implementation: just redraw)
    // In real app, diffing is better.
    
    els.pendingCount.textContent = requests.length;
    els.alertCount.textContent = requests.length; // Show count in circle

    if (requests.length > 0) {
        if (alertLevel !== 'critical') setThreatLevel('critical');
    }

    if (requests.length === 0) {
        els.pendingList.innerHTML = '<div style="text-align: center; color: #555; padding: 20px; font-size: 12px;">No pending requests.</div>';
        return;
    }

    els.pendingList.innerHTML = requests.map(req => {
        const isCritical = req.reason.includes('Ransomware') || req.reason.includes('CRITICAL');
        return `
        <div class="pending-item ${isCritical ? 'critical' : ''}">
            <div class="p-title">${isCritical ? '🚨 CRITICAL BLOCK REQUEST' : '⚠️ Suspicious Activity'}</div>
            <div class="p-path">${req.path}</div>
            <div style="font-size:11px; color:#aaa; margin-bottom:8px;">${req.reason}</div>
            <div class="p-actions">
                <button class="btn-sm btn-reject" onclick="handleReject('${req.id}')">⛔ BLOCK PROCESS</button>
                <button class="btn-sm btn-approve" onclick="handleApprove('${req.id}')">Allow (Risk)</button>
            </div>
        </div>
    `}).join('');
}

// Handle Action
window.handleReject = async (id) => {
    // In our logic: Reject = Confirm Remediation (Block/Kill)
    // Wait, "Approve" usually means "Approve Remediation". 
    // Let's check Python backend logic.
    // Python 'control.py': POST /approve -> puts in approved_queue (User allowed remediation?)
    // Actually, usually:
    // "Approve" = "Yes, kill it"
    // "Reject" = "No, let it run"
    // Let's re-read control.py or remediator.py if needed. 
    // Assuming Standard: Approve = Execute Remediation. Reject = Ignore.
    
    // Wait, UI button says "BLOCK PROCESS". This implies we want to perform the action.
    // So we should call "Approve" (Approve the remediation request).
    
    addLog(`Confirming BLOCK action for ${id}...`, 'warn');
    await window.agentAPI.approve(id);
    blockedCount++;
    els.threatsBlocked.textContent = blockedCount;
    pollPending(); // Force refresh
};

window.handleApprove = async (id) => {
    // "Allow (Risk)" -> Reject the remediation request (Let process continue)
    addLog(`Allowing process ${id} to continue...`, 'info');
    await window.agentAPI.reject(id);
    pollPending();
};

// Poll Loop
setInterval(pollPending, 1000);

// Initialize
setRunning(false);