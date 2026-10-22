let activeFullUrl = "";
let activeDomain = "";

// Initialize active URL
chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    if (tabs[0] && tabs[0].url) {
        activeFullUrl = tabs[0].url;
        try {
            activeDomain = new URL(activeFullUrl).hostname;
        } catch (e) {
            activeDomain = activeFullUrl;
        }
        document.getElementById('current-url').textContent = activeFullUrl.length > 55 
            ? activeFullUrl.substring(0, 52) + "..." 
            : activeFullUrl;
    }
});

// Tab Switching Logic
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const tabId = btn.getAttribute('data-tab');
        document.getElementById(tabId).classList.add('active');

        if (tabId === 'logs') loadForensicLogs();
        if (tabId === 'settings') loadSettingsAndAllowlist();
    });
});

// Scan Button Logic
document.getElementById('scanBtn').addEventListener('click', async () => {
    const scanBtn = document.getElementById('scanBtn');
    const resultDiv = document.getElementById('result');
    scanBtn.textContent = "Scanning...";

    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content.js']
    }, () => {
        chrome.tabs.sendMessage(tab.id, { action: "getDOM" }, async (response) => {
            const payload = response || { url: activeFullUrl, text: "" };
            try {
                const res = await fetch("http://127.0.0.1:5000/scan", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                renderScanResult(data);
            } catch (err) {
                resultDiv.style.display = "block";
                resultDiv.innerHTML = `<div class="card" style="color:#d32f2f; font-size:12px;">Cannot reach Local Engine. Make sure <b>python backend/app.py</b> is running.</div>`;
            }
            scanBtn.textContent = "Scan Website";
        });
    });
});

function renderScanResult(data) {
    const resultDiv = document.getElementById('result');
    resultDiv.style.display = "block";

    let statusClass = "safe-text", badgeClass = "badge-safe", label = "✅ SAFE";
    if (data.status === "Danger") {
        statusClass = "danger-text"; badgeClass = "badge-danger"; label = "⚠️ HIGH RISK";
    } else if (data.status === "Medium Risk") {
        statusClass = "medium-text"; badgeClass = "badge-medium"; label = "⚡ MEDIUM RISK";
    }

    const f = data.features || {};
    const suspiciousLen = (f.URL_Length || 0) > 75 ? '<span style="color:#d32f2f">Yes (' + f.URL_Length + ')</span>' : '<span>No (' + (f.URL_Length || 0) + ')</span>';
    const httpsMismatch = f.HttpsInHostname ? '<span style="color:#d32f2f">Yes</span>' : '<span>No</span>';

    let kwHtml = "";
    if (data.allowlisted) {
        kwHtml = `<p style="font-size:11px; color:#2e7d32; margin:0;">Domain <b>${data.domain}</b> is in your Trusted Allowlist. Scan bypassed to save CPU.</p>`;
    } else if (data.detected_keywords && data.detected_keywords.length > 0) {
        kwHtml = data.detected_keywords.map(k => `
            <div class="kw-item">
                <span>"${k.keyword}"</span>
                <span class="kw-weight">+${k.weight}</span>
            </div>
        `).join('');
    } else {
        kwHtml = `<p style="font-size:11px; color:#64748b; margin:0;">No Bahasa Malaysia or Manglish scam phrases detected.</p>`;
    }

    resultDiv.innerHTML = `
        <div class="card">
            <div class="alert-banner">
                <span class="${statusClass}">${label}</span>
                <span class="score-badge ${badgeClass}">${data.risk_score}%</span>
            </div>

            <div class="section-title">🔍 Feature Analysis</div>
            <div class="feature-grid">
                <div class="feature-box">URL Length > 75 ${suspiciousLen}</div>
                <div class="feature-box">Subdomain Dots <span>${f.NumDots || 0}</span></div>
                <div class="feature-box">Hyphens / Dashes <span>${f.NumDash || 0}</span></div>
                <div class="feature-box">HTTPS Anomaly ${httpsMismatch}</div>
            </div>

            <div class="section-title">🗣️ Localized NLP Detection</div>
            ${kwHtml}

            <div class="latency-tag">Inference Latency: <b>${data.latency_ms} ms</b></div>
        </div>
    `;
}

// Add current domain to Allowlist
document.getElementById('trustBtn').addEventListener('click', async () => {
    if (!activeDomain) return;
    await fetch("http://127.0.0.1:5000/allowlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: activeDomain })
    });
    alert(`Added ${activeDomain} to Trusted Allowlist!`);
});

// Load Forensic Logs
async function loadForensicLogs() {
    const listDiv = document.getElementById('logs-list');
    try {
        const res = await fetch("http://127.0.0.1:5000/logs");
        const logs = await res.json();
        if (logs.length === 0) {
            listDiv.innerHTML = "<p style='font-size:11px; color:#777;'>No scans logged yet.</p>";
            return;
        }
        listDiv.innerHTML = logs.map(l => {
            const color = l.Final_Status === "Danger" ? "#d32f2f" : (l.Final_Status === "Medium Risk" ? "#ed6c02" : "#2e7d32");
            const shortUrl = l.Scanned_URL.length > 32 ? l.Scanned_URL.substring(0, 30) + "..." : l.Scanned_URL;
            return `<div class="log-item">
                <span title="${l.Scanned_URL}">${shortUrl}</span>
                <strong style="color:${color}">${l.ML_Risk_Score}% (${l.Final_Status})</strong>
            </div>`;
        }).join('');
    } catch (e) {
        listDiv.innerHTML = "<p style='color:red; font-size:11px;'>Error loading logs.</p>";
    }
}

// Load Settings & Allowlist
async function loadSettingsAndAllowlist() {
    try {
        const resSet = await fetch("http://127.0.0.1:5000/settings");
        const set = await resSet.json();
        document.getElementById('thresh-slider').value = set.Risk_Threshold;
        document.getElementById('thresh-val').textContent = set.Risk_Threshold;

        const resAllow = await fetch("http://127.0.0.1:5000/allowlist");
        const allow = await resAllow.json();
        const allowDiv = document.getElementById('allowlist-items');
        if (allow.length === 0) {
            allowDiv.innerHTML = "<p style='font-size:11px; color:#777;'>No allowlisted domains.</p>";
        } else {
            allowDiv.innerHTML = allow.map(a => `
                <div class="log-item">
                    <span>${a.Domain_Name}</span>
                    <button data-domain="${a.Domain_Name}" class="remove-allow" style="background:none; border:none; color:#d32f2f; cursor:pointer; font-size:10px;">Remove</button>
                </div>
            `).join('');
            document.querySelectorAll('.remove-allow').forEach(btn => {
                btn.addEventListener('click', async () => {
                    await fetch("http://127.0.0.1:5000/allowlist", {
                        method: "DELETE",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ domain: btn.getAttribute('data-domain') })
                    });
                    loadSettingsAndAllowlist();
                });
            });
        }
    } catch (e) {}
}

document.getElementById('thresh-slider').addEventListener('input', (e) => {
    document.getElementById('thresh-val').textContent = e.target.value;
});

document.getElementById('saveSettingsBtn').addEventListener('click', async () => {
    const val = document.getElementById('thresh-slider').value;
    await fetch("http://127.0.0.1:5000/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ risk_threshold: val })
    });
    alert("Risk threshold updated!");
});