// Chart instances
let protocolChart = null;
let sizeChart = null;

// Packet data
let globalPackets = [];
let currentPage = 1;

// Chart.js default colors
Chart.defaults.color = '#94A3B8';
Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.05)';
Chart.defaults.font.family = "'Inter', sans-serif";

// Helper to determine current page
const isSnifferPage = document.getElementById('protocolFilter') !== null;

// DOM elements - Sniffer Page
const protocolSelect = document.getElementById('protocolFilter');
const categorySelect = document.getElementById('categoryFilter');
const searchBox = document.getElementById('searchBox');
const pageInfo = document.getElementById('pageInfo');
const prevBtn = document.getElementById('prevPage');
const nextBtn = document.getElementById('nextPage');
const testEmailBtn = document.getElementById('testEmail');

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

if (isSnifferPage) {
    // Event listeners
    document.getElementById('applyFilters').addEventListener('click', () => {
        currentPage = 1;
        loadPacketData();
    });

    searchBox.addEventListener('input', () => {
        currentPage = 1;
        renderPacketsTable();
    });

    prevBtn.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            renderPacketsTable();
        }
    });

    nextBtn.addEventListener('click', () => {
        const perPage = 25;
        const term = (searchBox.value || "").toLowerCase();
        const filtered = globalPackets.filter(pkt => {
            const combined = `${pkt.src || ''} ${pkt.dst || ''} ${pkt.proto} ${pkt.category} ${pkt.info}`.toLowerCase();
            return combined.includes(term);
        });
        const totalPages = Math.max(1, Math.ceil(filtered.length / perPage));
        if (currentPage < totalPages) {
            currentPage++;
            renderPacketsTable();
        }
    });

    if (testEmailBtn) {
        testEmailBtn.addEventListener('click', sendEmailTest);
    }

    setInterval(() => {
        if (!document.hidden) loadPacketData();
    }, 5000);
    setInterval(() => {
        if (!document.hidden) loadSystemStatus();
    }, 15000);
    // Initial load
    loadSystemStatus();
    loadPacketData();
}

// Load packet sniffer data
async function loadPacketData() {
    if (!isSnifferPage) return;
    try {
        const proto = protocolSelect.value;
        const cat = categorySelect.value;

        const res = await fetch(`/data?protocol=${proto}&category=${cat}&limit=200`);
        const data = await res.json();

        // Update stats
        document.getElementById('totalPackets').innerText = data.total;
        document.getElementById('protocolCount').innerText = Object.keys(data.stats).length;
        document.getElementById('categoryCount').innerText = Object.keys(data.cat_stats).length;
        updateCaptureStatus(data.capture_status);

        globalPackets = data.packets.slice().reverse();

        updateProtocolChart(data.stats);
        updateSizeChart(data.time_labels, data.sizes);
        renderPacketsTable();
    } catch (error) {
        console.error('Error loading packet data:', error);
        updateCaptureStatus({ running: false, error: 'Unable to reach dashboard data API.' });
    }
}

function updateCaptureStatus(status) {
    const badge = document.getElementById('captureStatusBadge');
    const text = document.getElementById('captureStatusText');
    if (!badge || !text) return;

    const error = status && status.error;
    const running = Boolean(status && status.running);
    if (running && !error) {
        text.innerText = 'Live Sensor Active';
        badge.classList.remove('sensor-warning');
        return;
    }

    text.innerText = error ? 'Sensor Needs Attention' : 'Sensor Inactive';
    badge.classList.add('sensor-warning');
    badge.title = error || 'Packet capture is not running.';
}

async function loadSystemStatus() {
    try {
        const response = await fetch('/system_status');
        const status = await response.json();
        updateSystemStatus(status);
    } catch (error) {
        console.error('Error loading system status:', error);
        updateSystemStatus({
            database: { error: 'Unable to reach status API.' },
            email: { ready: false, enabled: false }
        });
    }
}

function csrfToken() {
    return document.querySelector('input[name="csrf_token"]')?.value || '';
}

async function sendEmailTest() {
    if (!testEmailBtn) return;
    const originalText = testEmailBtn.innerHTML;
    testEmailBtn.disabled = true;
    testEmailBtn.innerHTML = '<i class="bi bi-hourglass-split"></i><span>Testing</span>';
    try {
        const response = await fetch('/email_test', {
            method: 'POST',
            headers: { 'X-CSRF-Token': csrfToken() }
        });
        const payload = await response.json();
        const email = payload.email || {};
        await loadSystemStatus();
        if (!response.ok || !payload.sent) {
            const reason = email.reason || 'Email test failed.';
            window.alert(reason);
        } else {
            window.alert('Email test alert sent. Check your inbox.');
        }
    } catch (error) {
        window.alert(`Email test failed: ${error.message}`);
        await loadSystemStatus();
    } finally {
        testEmailBtn.disabled = false;
        testEmailBtn.innerHTML = originalText;
    }
}

function updateSystemStatus(status) {
    const emailStatus = document.getElementById('emailStatus');
    const emailIcon = document.getElementById('emailStatusIcon');
    const databaseStatus = document.getElementById('databaseStatus');
    if (!emailStatus || !emailIcon || !databaseStatus) return;

    const email = status.email || {};
    emailIcon.classList.remove('green', 'yellow', 'red');
    if (email.ready) {
        emailStatus.innerText = 'Ready';
        emailIcon.classList.add('green');
    } else if (email.enabled) {
        emailStatus.innerText = 'Needs Setup';
        emailIcon.classList.add('yellow');
    } else {
        emailStatus.innerText = 'Disabled';
        emailIcon.classList.add('red');
    }

    const database = status.database || {};
    if (database.error) {
        databaseStatus.innerText = `Database: ${database.error}`;
        return;
    }
    if (email.reason) {
        databaseStatus.innerText = `Email: ${email.reason}`;
        databaseStatus.title = email.reason;
        return;
    }
    const backend = database.backend || 'unknown';
    const count = database.intrusion_logs ?? 0;
    databaseStatus.innerText = `Database: ${backend}, ${count} alerts`;
    databaseStatus.title = databaseStatus.innerText;
}

// Update protocol chart
function updateProtocolChart(stats) {
    const ctx = document.getElementById('protocolChart').getContext('2d');
    const labels = Object.keys(stats);
    const values = Object.values(stats);

    if (!protocolChart) {
        protocolChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels,
                datasets: [{
                    label: 'Packets',
                    data: values,
                    backgroundColor: [
                        'rgba(0, 240, 255, 0.8)',
                        'rgba(255, 51, 102, 0.8)',
                        'rgba(0, 230, 118, 0.8)',
                        'rgba(255, 234, 0, 0.8)',
                        'rgba(168, 85, 247, 0.8)'
                    ],
                    borderWidth: 0,
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { display: false }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' }
                    }
                }
            }
        });
    } else {
        protocolChart.data.labels = labels;
        protocolChart.data.datasets[0].data = values;
        protocolChart.update();
    }
}

// Update size chart
function updateSizeChart(timeLabels, sizes) {
    const ctx = document.getElementById('sizeChart').getContext('2d');

    if (!sizeChart) {
        sizeChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: timeLabels,
                datasets: [{
                    label: 'Packet Length',
                    data: sizes,
                    borderColor: '#00F0FF',
                    backgroundColor: 'rgba(0, 240, 255, 0.1)',
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 0,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { display: false }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' }
                    }
                }
            }
        });
    } else {
        sizeChart.data.labels = timeLabels;
        sizeChart.data.datasets[0].data = sizes;
        sizeChart.update();
    }
}

// Render packets table
function renderPacketsTable() {
    const tbody = document.getElementById('packetsTable');
    tbody.innerHTML = "";

    const term = (searchBox.value || "").toLowerCase();
    const perPage = 25;

    // Filter by search
    const filtered = globalPackets.filter(pkt => {
        const combined = `${pkt.src || ''} ${pkt.dst || ''} ${pkt.proto} ${pkt.category} ${pkt.info}`.toLowerCase();
        return combined.includes(term);
    });

    const totalPages = Math.max(1, Math.ceil(filtered.length / perPage));
    if (currentPage > totalPages) currentPage = totalPages;

    const start = (currentPage - 1) * perPage;
    const end = start + perPage;
    const pageData = filtered.slice(start, end);

    pageData.forEach(pkt => {
        const tr = document.createElement('tr');
        
        let protoClass = 'badge';
        if (pkt.proto === 'TCP') protoClass += ' badge-tcp';
        else if (pkt.proto === 'UDP') protoClass += ' badge-udp';
        else if (pkt.proto === 'ICMP') protoClass += ' badge-icmp';
        
        tr.innerHTML = `
            <td class="font-monospace text-secondary">${escapeHtml(pkt.time)}</td>
            <td class="font-monospace">${escapeHtml(pkt.src || 'N/A')}</td>
            <td class="font-monospace">${escapeHtml(pkt.dst || 'N/A')}</td>
            <td><span class="${protoClass}">${escapeHtml(pkt.proto)}</span></td>
            <td>${escapeHtml(pkt.len)} B</td>
            <td class="text-secondary" style="max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(pkt.info)}</td>
        `;
        tbody.appendChild(tr);
    });

    pageInfo.innerText = `${currentPage} / ${totalPages}`;
}
