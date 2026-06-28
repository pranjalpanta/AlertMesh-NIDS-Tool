let attackTypeChart = null;
let severityChart = null;
let latestLogs = [];
let latestFilteredTotal = 0;
let refreshTimer = null;
let expandedLogId = null;

const clearStorageKey = 'alertmeshIntrusionClearedAfter';

Chart.defaults.color = '#e5e7eb';
Chart.defaults.borderColor = 'rgba(148, 163, 184, 0.2)';

const searchInput = document.getElementById('intrusionSearch');
const severityFilter = document.getElementById('severityFilter');
const attackTypeFilter = document.getElementById('attackTypeFilter');
const applyFiltersBtn = document.getElementById('applyIntrusionFilters');
const resetFiltersBtn = document.getElementById('resetIntrusionFilters');
const clearViewBtn = document.getElementById('clearLogView');
const showPreviousBtn = document.getElementById('showPreviousLogs');
const deleteVisibleBtn = document.getElementById('deleteVisibleLogs');
const viewNote = document.getElementById('viewNote');
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';

function installDetailStyles() {
    if (document.getElementById('alert-detail-runtime-styles')) return;
    const style = document.createElement('style');
    style.id = 'alert-detail-runtime-styles';
    style.textContent = `
        .row-action-group {
            display: inline-flex !important;
            align-items: center !important;
            justify-content: flex-end !important;
            gap: 14px !important;
            min-width: 88px !important;
        }
        .row-detail-btn,
        .row-delete-btn {
            width: 36px !important;
            height: 36px !important;
            display: inline-flex !important;
            align-items: center !important;
            justify-content: center !important;
            border-radius: 8px !important;
            cursor: pointer !important;
            line-height: 1 !important;
            flex: 0 0 36px !important;
        }
        .row-detail-btn {
            border: 1px solid rgba(0, 212, 255, 0.34) !important;
            background: rgba(0, 212, 255, 0.09) !important;
            color: #00d4ff !important;
        }
        .row-detail-btn:hover,
        .row-detail-btn.active {
            background: rgba(0, 212, 255, 0.18) !important;
            border-color: rgba(0, 212, 255, 0.58) !important;
        }
        .alert-detail-row td {
            padding: 0 16px 20px !important;
            background: rgba(2, 6, 23, 0.35) !important;
        }
        .alert-detail-card {
            border: 1px solid rgba(148, 163, 184, 0.16) !important;
            border-radius: 12px !important;
            background: rgba(8, 13, 27, 0.96) !important;
            padding: 18px !important;
            box-shadow: inset 3px 0 0 rgba(0, 212, 255, 0.5) !important;
        }
        .detail-header {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 16px;
        }
        .detail-title {
            font-size: 0.98rem;
            font-weight: 700;
            color: #f8fafc;
            margin-bottom: 4px;
        }
        .detail-subtitle {
            color: #94a3b8;
            font-size: 0.84rem;
        }
        .detail-grid {
            display: grid !important;
            grid-template-columns: repeat(4, minmax(150px, 1fr)) !important;
            gap: 12px !important;
            margin-bottom: 16px !important;
        }
        .detail-item {
            min-width: 0 !important;
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 8px;
            background: rgba(15, 23, 42, 0.66);
            padding: 10px 12px;
        }
        .detail-label {
            color: #64748b !important;
            font-size: 0.66rem !important;
            font-weight: 800 !important;
            letter-spacing: 1px !important;
            text-transform: uppercase !important;
            margin-bottom: 5px !important;
        }
        .detail-value {
            color: #f8fafc !important;
            overflow-wrap: anywhere !important;
        }
        .detail-section {
            border-top: 1px solid rgba(148, 163, 184, 0.12);
            padding-top: 14px;
            margin-top: 14px;
        }
        .detail-note {
            color: #cbd5e1 !important;
            line-height: 1.55 !important;
            max-width: 1100px;
        }
        .detail-command {
            display: inline-block;
            margin-top: 8px;
            padding: 8px 10px;
            border-radius: 8px;
            background: rgba(2, 6, 23, 0.72);
            border: 1px solid rgba(148, 163, 184, 0.14);
            color: #e2e8f0;
            white-space: pre-wrap;
        }
        .detail-raw-log {
            margin: 8px 0 0;
            padding: 10px;
            max-height: 180px;
            overflow: auto;
            border-radius: 8px;
            border: 1px solid rgba(148, 163, 184, 0.14);
            background: rgba(2, 6, 23, 0.78);
            color: #cbd5e1;
            white-space: pre-wrap;
        }
        @media (max-width: 1200px) {
            .detail-grid {
                grid-template-columns: repeat(2, minmax(150px, 1fr)) !important;
            }
        }
        @media (max-width: 700px) {
            .detail-header {
                flex-direction: column;
            }
            .detail-grid {
                grid-template-columns: 1fr !important;
            }
        }
    `;
    document.head.appendChild(style);
}

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

function toSqlTimestamp(date) {
    const pad = value => String(value).padStart(2, '0');
    return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
}

function parseUtcTimestamp(value) {
    if (!value) return null;
    const normalized = String(value).includes('T')
        ? String(value)
        : `${String(value).replace(' ', 'T')}Z`;
    const parsed = new Date(normalized.endsWith('Z') ? normalized : `${normalized}Z`);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function buildQueryParams() {
    const params = new URLSearchParams();
    const severity = severityFilter.value || 'ALL';
    const attackType = attackTypeFilter.value || 'ALL';
    const searchTerm = searchInput.value.trim();
    const clearedAfter = localStorage.getItem(clearStorageKey);

    if (severity !== 'ALL') params.set('severity', severity);
    if (attackType !== 'ALL') params.set('attack_type', attackType);
    if (searchTerm) params.set('q', searchTerm);
    if (clearedAfter) params.set('since', clearedAfter);

    return params;
}

function updateViewNote() {
    const clearedAfter = localStorage.getItem(clearStorageKey);
    if (!clearedAfter) {
        viewNote.textContent = '';
        return;
    }

    const parsed = parseUtcTimestamp(clearedAfter);
    viewNote.textContent = `Previous alerts are hidden. Showing alerts after ${(parsed || new Date()).toLocaleString()}.`;
}

function syncFilterOptions(options) {
    syncSelectOptions(severityFilter, options.severities || [], 'All Severities');
    syncSelectOptions(attackTypeFilter, options.attack_types || [], 'All Attack Types');
}

function syncSelectOptions(select, values, defaultLabel) {
    const currentValue = select.value || 'ALL';
    select.innerHTML = `<option value="ALL">${defaultLabel}</option>`;

    values.forEach(value => {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = value;
        select.appendChild(option);
    });

    select.value = Array.from(select.options).some(option => option.value === currentValue)
        ? currentValue
        : 'ALL';
}

async function loadIntrusionData() {
    try {
        const params = buildQueryParams();
        const res = await fetch(`/intrusion_data?${params.toString()}`);
        const data = await res.json();

        if (data.error) {
            console.error('Error loading intrusion data:', data.error);
            document.getElementById('intrusionTable').innerHTML =
                '<tr><td colspan="9" class="text-center text-danger">Error loading data.</td></tr>';
            return;
        }

        latestLogs = data.logs || [];
        latestFilteredTotal = data.stats.filtered_total || latestLogs.length;
        document.getElementById('totalAlertsToday').innerText = data.stats.total_today;
        document.getElementById('highSeverityCount').innerText = data.stats.high_severity;
        document.getElementById('mostAttackedPort').innerText = data.stats.most_attacked_port;

        syncFilterOptions(data.filter_options || {});
        renderIntrusionTable(latestLogs);
        updateViewNote();
        updateChartsSafely(data.attack_stats || [], data.severity_stats || []);
    } catch (error) {
        console.error('Error loading intrusion data:', error);
        document.getElementById('intrusionTable').innerHTML =
            '<tr><td colspan="9" class="text-center text-danger">Error loading data.</td></tr>';
    }
}

function updateChartsSafely(attackStats, severityStats) {
    if (typeof Chart === 'undefined') {
        console.warn('Chart.js is unavailable; intrusion log table will still render.');
        return;
    }

    try {
        updateAttackTypeChart(attackStats);
        updateSeverityChart(severityStats);
    } catch (error) {
        console.error('Error rendering intrusion charts:', error);
    }
}

function updateAttackTypeChart(attackStats) {
    const ctx = document.getElementById('attackTypeChart').getContext('2d');
    const labels = attackStats.map(s => s.attack_type);
    const values = attackStats.map(s => s.count);

    if (!attackTypeChart) {
        attackTypeChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels,
                datasets: [{
                    label: 'Count',
                    data: values,
                    backgroundColor: [
                        'rgba(220, 20, 60, 0.8)',
                        'rgba(0, 56, 147, 0.8)',
                        'rgba(34, 197, 94, 0.8)',
                        'rgba(234, 179, 8, 0.8)',
                        'rgba(249, 115, 22, 0.8)',
                        'rgba(168, 85, 247, 0.8)'
                    ],
                    borderWidth: 0,
                    borderRadius: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { maxRotation: 45, minRotation: 45 }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(148, 163, 184, 0.1)' }
                    }
                }
            }
        });
    } else {
        attackTypeChart.data.labels = labels;
        attackTypeChart.data.datasets[0].data = values;
        attackTypeChart.update();
    }
}

function updateSeverityChart(severityStats) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    const labels = severityStats.map(s => s.severity);
    const values = severityStats.map(s => s.count);
    const colors = {
        CRITICAL: '#991B1B',
        HIGH: '#DC143C',
        MEDIUM: '#f97316',
        LOW: '#eab308'
    };

    if (!severityChart) {
        severityChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels,
                datasets: [{
                    data: values,
                    backgroundColor: labels.map(label => colors[label] || '#6b7280'),
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { padding: 20, usePointStyle: true }
                    }
                },
                cutout: '60%'
            }
        });
    } else {
        severityChart.data.labels = labels;
        severityChart.data.datasets[0].data = values;
        severityChart.data.datasets[0].backgroundColor = labels.map(label => colors[label] || '#6b7280');
        severityChart.update();
    }
}

function logId(log) {
    return String(log.id ?? `${log.timestamp}-${log.src_ip}-${log.dst_ip}-${log.attack_type}`);
}

function targetText(log) {
    return `${log.dst_ip || 'N/A'}:${log.dst_port || 'N/A'}`;
}

function attackExplanation(log) {
    const attackType = log.attack_type || 'UNKNOWN';
    const destination = targetText(log);
    const source = log.src_ip || 'unknown source';
    const explanations = {
        ICMP_ATTACK: `Repeated or oversized ICMP traffic was observed from ${source} to ${log.dst_ip || 'the target host'}. This matches the Kali ping probe tests.`,
        PORT_SCAN: `${source} touched multiple destination ports on ${log.dst_ip || 'the target host'} in a short window. This matches the nmap port scan tests.`,
        BRUTE_FORCE: `Repeated connection attempts were observed from ${source} to ${destination}. This matches repeated SSH/FTP/RDP connection attempt tests.`,
        EXPOSED_SERVICE_ACCESS: `${source} repeatedly probed an exposed service at ${destination}. This matches SMB/RDP/Telnet service probe tests.`
    };
    return explanations[attackType] || `AlertMesh accepted this ${attackType} alert for ${source} targeting ${destination}.`;
}

function likelyKaliCommand(log) {
    const target = log.dst_ip || '$TARGET';
    const port = log.dst_port || '';
    const commands = {
        ICMP_ATTACK: `ping -c 6 ${target}\nping -c 1 -s 1400 ${target}`,
        PORT_SCAN: `sudo nmap -sS -p 20-30 ${target}`,
        BRUTE_FORCE: port
            ? `for i in {1..6}; do nc -vz -w 1 ${target} ${port}; done`
            : `for i in {1..6}; do nc -vz -w 1 ${target} 22; done`,
        EXPOSED_SERVICE_ACCESS: port
            ? `for i in {1..4}; do nc -vz -w 1 ${target} ${port}; done`
            : `for i in {1..4}; do nc -vz -w 1 ${target} 445; done`
    };
    return commands[log.attack_type] || `nmap -sV ${target}`;
}

function evidenceSummary(log) {
    const parts = [
        `Observed ${log.protocol || 'network'} traffic`,
        `from ${log.src_ip || 'unknown source'}${log.src_port ? `:${log.src_port}` : ''}`,
        `to ${log.dst_ip || 'unknown target'}${log.dst_port ? `:${log.dst_port}` : ''}`,
        `classified as ${log.attack_type || 'UNKNOWN'}.`
    ];
    return parts.join(' ');
}

function rawLogObject(log) {
    return JSON.stringify({
        timestamp: log.timestamp,
        source_ip: log.src_ip,
        source_port: log.src_port || null,
        destination_ip: log.dst_ip,
        destination_port: log.dst_port || null,
        protocol: log.protocol || null,
        attack_type: log.attack_type,
        severity: log.severity,
        origin: log.country || 'Unknown',
        os_estimate: log.detected_os || 'Unknown',
        detector: log.source || 'unknown',
        analysis_note: log.analysis_note || null,
        signature_id: log.signature_id || null,
        classification: log.classification || null
    }, null, 2);
}

function detailItem(label, value, cssClass = '') {
    return `
        <div class="detail-item">
            <div class="detail-label">${escapeHtml(label)}</div>
            <div class="detail-value ${cssClass}">${escapeHtml(value ?? 'N/A')}</div>
        </div>
    `;
}

function renderAlertDetails(log) {
    return `
        <tr class="alert-detail-row" data-detail-for="${escapeHtml(logId(log))}">
            <td colspan="9">
                <div class="alert-detail-card">
                    <div class="detail-header">
                        <div>
                            <div class="detail-title">${escapeHtml(log.attack_type || 'Alert Detail')}</div>
                            <div class="detail-subtitle">${escapeHtml(evidenceSummary(log))}</div>
                        </div>
                        <span class="badge ${log.severity === 'CRITICAL' ? 'badge-critical' : log.severity === 'HIGH' ? 'badge-high' : log.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low'}">${escapeHtml(log.severity || 'UNKNOWN')}</span>
                    </div>
                    <div class="detail-grid">
                        ${detailItem('Timestamp', log.timestamp || 'N/A', 'mono')}
                        ${detailItem('Source IP', log.src_ip || 'N/A', 'mono')}
                        ${detailItem('Protocol', log.protocol || 'N/A', 'mono')}
                        ${detailItem('Source Port', log.src_port || 'N/A', 'mono')}
                        ${detailItem('Destination Port', log.dst_port || 'N/A', 'mono')}
                        ${detailItem('Target', targetText(log), 'mono')}
                        ${detailItem('Detector', log.source || 'unknown', 'mono')}
                        ${detailItem('Signature ID', log.signature_id || 'N/A', 'mono')}
                        ${detailItem('Classification', log.classification || 'N/A')}
                    </div>
                    <div class="detail-section">
                        <div class="detail-label">Why This Alert Was Logged</div>
                        <div class="detail-note">${escapeHtml(log.analysis_note || 'No analysis note was stored for this alert.')}</div>
                    </div>
                    <div class="detail-section">
                        <div class="detail-label">Attack Test Match</div>
                        <div class="detail-note">${escapeHtml(attackExplanation(log))}</div>
                        <code class="detail-command mono">${escapeHtml(likelyKaliCommand(log))}</code>
                    </div>
                    <div class="detail-section">
                        <div class="detail-label">Stored Log Record</div>
                        <pre class="detail-raw-log mono">${escapeHtml(rawLogObject(log))}</pre>
                    </div>
                </div>
            </td>
        </tr>
    `;
}

function renderIntrusionTable(logs) {
    const tbody = document.getElementById('intrusionTable');
    tbody.innerHTML = '';

    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="text-center text-white-50">No intrusion logs match this view.</td></tr>';
        return;
    }

    logs.forEach(log => {
        const currentLogId = logId(log);
        const tr = document.createElement('tr');
        const timestamp = parseUtcTimestamp(log.timestamp);
        const formattedTime = !timestamp
            ? log.timestamp
            : timestamp.toLocaleString();
        const severityClass = log.severity === 'CRITICAL' ? 'badge-critical'
            : log.severity === 'HIGH' ? 'badge-high'
            : log.severity === 'MEDIUM' ? 'badge-medium'
            : 'badge-low';

        tr.innerHTML = `
            <td class="mono text-secondary">${escapeHtml(formattedTime)}</td>
            <td class="mono">${escapeHtml(log.src_ip)}</td>
            <td>${escapeHtml(log.country || 'Unknown')}</td>
            <td class="text-center"><span class="mono">${escapeHtml(log.detected_os || 'Unknown')}</span></td>
            <td>${escapeHtml(log.attack_type)}</td>
            <td><span class="badge ${severityClass}">${escapeHtml(log.severity)}</span></td>
            <td class="mono">${escapeHtml(log.source || 'unknown')}</td>
            <td class="mono">${escapeHtml(targetText(log))}</td>
            <td>
                <div class="row-action-group">
                    <button class="row-detail-btn ${expandedLogId === currentLogId ? 'active' : ''}" data-log-id="${escapeHtml(currentLogId)}" title="Show alert details">
                        <i class="bi bi-info-circle"></i>
                    </button>
                    <button class="row-delete-btn" data-log-id="${escapeHtml(log.id)}" title="Delete this alert">
                        <i class="bi bi-trash3"></i>
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
        if (expandedLogId === currentLogId) {
            tr.insertAdjacentHTML('afterend', renderAlertDetails(log));
        }
    });
}

async function deleteLogs(payload) {
    const res = await fetch('/intrusion_logs/delete', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify(payload)
    });
    const data = await res.json();

    if (!res.ok || data.error) {
        throw new Error(data.error || 'Delete failed');
    }

    return data.deleted || 0;
}

applyFiltersBtn.addEventListener('click', loadIntrusionData);

searchInput.addEventListener('keydown', event => {
    if (event.key === 'Enter') {
        loadIntrusionData();
    }
});

resetFiltersBtn.addEventListener('click', () => {
    searchInput.value = '';
    severityFilter.value = 'ALL';
    attackTypeFilter.value = 'ALL';
    localStorage.removeItem(clearStorageKey);
    loadIntrusionData();
});

clearViewBtn.addEventListener('click', () => {
    localStorage.setItem(clearStorageKey, toSqlTimestamp(new Date()));
    loadIntrusionData();
});

showPreviousBtn.addEventListener('click', () => {
    localStorage.removeItem(clearStorageKey);
    loadIntrusionData();
});

deleteVisibleBtn.addEventListener('click', async () => {
    if (latestFilteredTotal === 0) return;
    const filters = Object.fromEntries(buildQueryParams().entries());
    const isFullPurge = Object.keys(filters).length === 0;
    const prompt = isFullPurge
        ? `Permanently delete ALL ${latestFilteredTotal} intrusion alert(s)?`
        : `Permanently delete ${latestFilteredTotal} intrusion alert(s) matching this view?`;
    const ok = window.confirm(prompt);
    if (!ok) return;

    try {
        const payload = isFullPurge
            ? { delete_all: true, confirm: 'DELETE_ALL' }
            : { delete_filtered: true, filters };
        const deleted = await deleteLogs(payload);
        window.alert(`Deleted ${deleted} intrusion alert(s).`);
        await loadIntrusionData();
    } catch (error) {
        window.alert(error.message);
    }
});

document.getElementById('intrusionTable').addEventListener('click', async event => {
    const detailButton = event.target.closest('.row-detail-btn');
    if (detailButton) {
        expandedLogId = expandedLogId === detailButton.dataset.logId
            ? null
            : detailButton.dataset.logId;
        renderIntrusionTable(latestLogs);
        return;
    }

    const button = event.target.closest('.row-delete-btn');
    if (!button) return;

    const ok = window.confirm('Permanently delete this intrusion alert?');
    if (!ok) return;

    try {
        await deleteLogs({ id: button.dataset.logId });
        await loadIntrusionData();
    } catch (error) {
        window.alert(error.message);
    }
});

installDetailStyles();
loadIntrusionData();
refreshTimer = setInterval(() => {
    if (!document.hidden) loadIntrusionData();
}, 15000);
