let pollInterval = null;
let isRunning = false;

function toggleMonitoring() {
    if (isRunning) {
        stopMonitoring();
    } else {
        startMonitoring();
    }
}

function setButtonState(running) {
    const btn = document.getElementById('toggle-btn');
    if (running) {
        btn.innerText = 'Stop Monitoring';
        btn.className = 'btn secondary btn-lg'; // Visual distinction
        btn.style.borderColor = '#ef4444';
        btn.style.color = '#ef4444';
    } else {
        btn.innerText = 'Start Monitoring';
        btn.className = 'btn primary btn-lg';
        btn.style.borderColor = ''; // reset
        btn.style.color = '';
    }
}

function startMonitoring() {
    // Instant feedback - Yellow (Starting is a transitional state, essentially "stopped" until confirmed running) or just keep as is but user wanted Yellow for Stop.
    // Let's use Yellow for "Wait/Yellow" state.
    document.getElementById('status-indicator').className = 'status-badge warning';
    document.getElementById('status-indicator').innerText = 'STARTING...';

    document.getElementById('toggle-btn').disabled = true;

    fetch('/api/start')
        .then(response => response.json())
        .then(data => {
            document.getElementById('toggle-btn').disabled = false;
            isRunning = true;
            setButtonState(true);

            document.getElementById('system-msg').innerText = "Monitoring Running...";
            pollStatus(); // Immediate poll

            // Get interval from config input or default
            const interval = 2000;
            pollInterval = setInterval(pollStatus, interval);
        });
}

function stopMonitoring() {
    // Instant feedback
    document.getElementById('status-indicator').className = 'status-badge warning';
    document.getElementById('status-indicator').innerText = 'STOPPING...';
    document.getElementById('toggle-btn').disabled = true;

    fetch('/api/stop')
        .then(response => response.json())
        .then(data => {
            document.getElementById('toggle-btn').disabled = false;
            isRunning = false;
            setButtonState(false);

            document.getElementById('status-indicator').className = 'status-badge warning'; // Yellow for STOPPED
            document.getElementById('status-indicator').innerText = 'STOPPED';
            document.getElementById('system-msg').innerText = "Monitoring Stopped.";

            if (pollInterval) clearInterval(pollInterval);
        });
}

function exportCSV() {
    const link = document.createElement('a');
    link.href = '/api/export_csv';
    link.target = '_blank';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function pollStatus() {
    fetch('/api/status')
        .then(response => response.json())
        .then(state => {
            updateUI(state);
        })
        .catch(err => console.error("Polling error:", err));
}

function updateUI(state) {
    if (!state.running) {
        // If we think we are running but server stopped
        if (isRunning) {
            isRunning = false;
            setButtonState(false);
            document.getElementById('status-indicator').className = 'status-badge warning'; // Yellow
            document.getElementById('status-indicator').innerText = 'STOPPED';
            if (pollInterval) clearInterval(pollInterval);
        }
        return;
    }

    // Update global status
    const indicator = document.getElementById('status-indicator');
    if (state.error_mode) {
        indicator.className = 'status-badge offline'; // Red
        indicator.innerText = 'ERROR'; // Explicit text change per request
    } else {
        indicator.className = 'status-badge online'; // Green
        indicator.innerText = 'ONLINE'; // Explicit text change per request
    }

    const data = state.data;
    if (!data) return; // No data yet

    // Update Cards
    updateCard('card-loopback', data.loopback, data.loopback_latency);
    updateCard('card-gateway', data.gateway, data.gateway_latency, data.gateway_ip);
    updateCard('card-isp', data.dns_isp, data.dns_isp_latency, data.dns_isp_ip);
    updateCard('card-hinet', data.dns_hinet, data.dns_hinet_latency, data.dns_hinet_ip);
    updateCard('card-google', data.dns_google, data.dns_google_latency, data.dns_google_ip);

    // Resolution
    const resCard = document.getElementById('card-resolution');
    resCard.querySelector('.val-ip').innerText = data.resolved_ip || '--';
    const resStatus = resCard.querySelector('.val-status');
    setBooleanStatus(resStatus, data.dns_resolution);

    // Card Titles & Labels based on config
    const updateTitle = (id, currentIp, defaultIp, altTitle, defaultTitle, labelId) => {
        const card = document.getElementById(id);
        const label = document.getElementById(labelId);

        let titleText = defaultTitle;
        if (currentIp && currentIp !== defaultIp) {
            titleText = altTitle;
        }

        // Update Card
        if (card) {
            card.querySelector('h3').innerText = titleText;
        }
        // Update Label
        if (label) {
            label.innerText = titleText;
        }
    };

    // Default IPs for check
    updateTitle('card-isp', data.dns_isp_ip, '140.120.1.2', 'DNS 1', 'ISP DNS', 'lbl-target-isp');
    updateTitle('card-hinet', data.dns_hinet_ip, '168.95.1.1', 'DNS 2', 'Hinet DNS', 'lbl-target-hinet');
    updateTitle('card-google', data.dns_google_ip, '8.8.8.8', 'DNS 3', 'Google DNS', 'lbl-target-google');



    // Update Logs
    const logContainer = document.getElementById('log-container');
    const logs = (state.display_log || state.log).slice().reverse();
    logContainer.innerHTML = logs.map(entry => {
        const time = entry.time.split(' ')[1];
        const isError = entry.failure_annotation && entry.failure_annotation.length > 0;
        const msg = isError ? entry.failure_annotation : "All checks passed";
        const cls = isError ? "log-entry error" : "log-entry";
        return `<div class="${cls}">[${time}] ${msg}</div>`;
    }).join('');
}

function updateCard(cardId, success, latency, ip = null) {
    const card = document.getElementById(cardId);
    if (!card) return;

    if (ip !== null) {
        card.querySelector('.val-ip').innerText = ip;
    }

    const statusEl = card.querySelector('.val-status');
    setBooleanStatus(statusEl, success);

    const latEl = card.querySelector('.val-latency');
    if (latency !== null && latency !== undefined) {
        latEl.innerText = latency + 'ms';
    } else {
        latEl.innerText = '--';
    }
}

function setBooleanStatus(element, isSuccess) {
    if (isSuccess === true) {
        element.innerText = "OK";
        element.className = "val-status status-good";
    } else if (isSuccess === false) {
        element.innerText = "FAIL";
        element.className = "val-status status-bad";
    } else {
        element.innerText = "Waiting...";
        element.className = "val-status status-wait";
    }
}

// Config Functions
let initialConfig = {};

function loadConfig() {
    fetch('/api/config')
        .then(res => res.json())
        .then(config => {
            initialConfig = { ...config }; // store copy

            const setVal = (id, val) => {
                const el = document.getElementById(id);
                if (el) el.value = val;
            };

            setVal('cfg-interval', config.interval_seconds);
            setVal('cfg-panic', config.continuous_monitoring_seconds);
            setVal('cfg-ping-freq', config.ping_frequency);
            setVal('cfg-target-gateway', config.target_gateway);
            setVal('cfg-target-isp', config.target_isp_dns);
            setVal('cfg-target-hinet', config.target_hinet_dns);
            setVal('cfg-target-google', config.target_google_dns);
            setVal('cfg-target-resolution', config.target_resolution);

            checkChanges(); // Reset button state
        });
}

function checkChanges() {
    const getVal = (id) => document.getElementById(id).value;
    const btn = document.getElementById('update-targets-btn');
    if (!btn) return;

    const current = {
        interval_seconds: parseInt(getVal('cfg-interval')),
        continuous_monitoring_seconds: parseInt(getVal('cfg-panic')),
        ping_frequency: parseInt(getVal('cfg-ping-freq')),
        target_gateway: getVal('cfg-target-gateway'),
        target_isp_dns: getVal('cfg-target-isp'),
        target_hinet_dns: getVal('cfg-target-hinet'),
        target_google_dns: getVal('cfg-target-google'),
        target_resolution: getVal('cfg-target-resolution')
    };

    let changed = false;
    for (const key in current) {
        if (String(current[key]) !== String(initialConfig[key])) {
            changed = true;
            break;
        }
    }

    if (changed) {
        btn.classList.add('success');
    } else {
        btn.classList.remove('success');
    }
}

function resetConfig() {
    if (!confirm("Reset all settings to default?")) return;

    const defaults = {
        interval_seconds: 10,
        continuous_monitoring_seconds: 60,
        ping_frequency: 3,
        target_gateway: 'AUTO',
        target_isp_dns: '140.120.1.2',
        target_hinet_dns: '168.95.1.1',
        target_google_dns: '8.8.8.8',
        target_resolution: 'www.google.com'
    };

    // Apply to inputs
    document.getElementById('cfg-interval').value = defaults.interval_seconds;
    document.getElementById('cfg-panic').value = defaults.continuous_monitoring_seconds;
    document.getElementById('cfg-ping-freq').value = defaults.ping_frequency;
    document.getElementById('cfg-target-gateway').value = defaults.target_gateway;
    document.getElementById('cfg-target-isp').value = defaults.target_isp_dns;
    document.getElementById('cfg-target-hinet').value = defaults.target_hinet_dns;
    document.getElementById('cfg-target-google').value = defaults.target_google_dns;
    document.getElementById('cfg-target-resolution').value = defaults.target_resolution;

    saveConfig(); // Save immediately
}

function saveConfig() {
    const getVal = (id) => document.getElementById(id).value;

    const interval = getVal('cfg-interval');
    const panic = getVal('cfg-panic');
    const freq = getVal('cfg-ping-freq');

    // Targets
    const targetGateway = getVal('cfg-target-gateway');
    const targetIsp = getVal('cfg-target-isp');
    const targetHinet = getVal('cfg-target-hinet');
    const targetGoogle = getVal('cfg-target-google');
    const targetRes = getVal('cfg-target-resolution');

    const newConfig = {
        interval_seconds: interval,
        continuous_monitoring_seconds: panic,
        ping_frequency: freq,
        target_gateway: targetGateway,
        target_isp_dns: targetIsp,
        target_hinet_dns: targetHinet,
        target_google_dns: targetGoogle,
        target_resolution: targetRes
    };

    fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newConfig)
    })
        .then(res => res.json())
        .then(data => {
            loadConfig();
            alert("Settings Saved!");
        });
}

// Auto-start on load - DISABLED
document.addEventListener('DOMContentLoaded', () => {
    loadConfig();
    // Monitor inputs for changes
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
        input.addEventListener('input', checkChanges);
    });

    // Initial status: STOPPED (Yellow)
    document.getElementById('status-indicator').innerText = 'STOPPED';
    document.getElementById('status-indicator').className = 'status-badge warning';

    // === Live Clock Definition ===
    function updateClock() {
        const now = new Date();
        const timeEl = document.querySelector('.live-clock .time');
        const dateEl = document.querySelector('.live-clock .date');

        if (timeEl && dateEl) {
            // Format Time
            const timeStr = now.toLocaleTimeString('en-US', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });

            // Format Date & Region
            const dateStr = now.toLocaleDateString('en-CA');
            const region = Intl.DateTimeFormat().resolvedOptions().timeZone;

            timeEl.innerText = timeStr;
            dateEl.innerText = `${dateStr} | ${region}`;
        }
    }

    // Start Clock
    setInterval(updateClock, 1000);
    updateClock(); // Initial call
});
