/* =========================================================
   NetShield IDS — Dashboard JavaScript
   Chart.js configuration, SSE real-time feed, counters
   ========================================================= */

/* --- Color Constants --- */
const COLORS = {
    cyan: '#00d4ff',
    purple: '#7c3aed',
    danger: '#ff3366',
    success: '#00ff88',
    warning: '#ffaa00',
    info: '#38bdf8',
    textSecondary: '#94a3b8',
    textMuted: '#64748b',
    border: 'rgba(0, 212, 255, 0.1)',
    gridLine: 'rgba(255, 255, 255, 0.04)',
    /* Model-specific colors */
    rf: '#00d4ff',
    xgb: '#7c3aed',
    lstm: '#ff3366',
    /* Attack-type colors */
    Normal: '#00ff88',
    DoS: '#ff3366',
    Probe: '#ffaa00',
    R2L: '#7c3aed',
    U2R: '#f87171',
};

/* --- Chart.js Global Defaults --- */
Chart.defaults.color = COLORS.textSecondary;
Chart.defaults.borderColor = COLORS.gridLine;
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 12;
Chart.defaults.plugins.legend.labels.usePointStyle = true;
Chart.defaults.plugins.legend.labels.padding = 16;
Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(15, 20, 50, 0.9)';
Chart.defaults.plugins.tooltip.borderColor = COLORS.border;
Chart.defaults.plugins.tooltip.borderWidth = 1;
Chart.defaults.plugins.tooltip.cornerRadius = 8;
Chart.defaults.plugins.tooltip.titleFont = { family: "'Inter', sans-serif", weight: '600' };
Chart.defaults.plugins.tooltip.bodyFont = { family: "'JetBrains Mono', monospace" };
Chart.defaults.plugins.tooltip.padding = 12;
Chart.defaults.responsive = true;
Chart.defaults.maintainAspectRatio = false;

/* =========================================================
   Utility Functions
   ========================================================= */

function formatTimestamp(date) {
    const d = date instanceof Date ? date : new Date(date);
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function getAttackBadgeClass(type) {
    if (!type || type === 'Normal') return 'badge-normal';
    return `badge-${type}`;
}

function animateCounter(element, target, duration = 1200) {
    if (!element) return;
    const start = parseInt(element.textContent) || 0;
    const range = target - start;
    if (range === 0) return;
    const startTime = performance.now();

    function step(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        /* Ease out cubic */
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + range * eased);
        element.textContent = current.toLocaleString();
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

function animatePercentage(element, target, duration = 1200) {
    if (!element) return;
    const startVal = parseFloat(element.textContent) || 0;
    const range = target - startVal;
    if (Math.abs(range) < 0.01) return;
    const startTime = performance.now();

    function step(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = startVal + range * eased;
        element.textContent = current.toFixed(1) + '%';
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

/* =========================================================
   Dashboard State
   ========================================================= */
let dashboardState = {
    totalConnections: 0,
    threats: 0,
    attackCounts: { DoS: 0, Probe: 0, R2L: 0, U2R: 0 },
    timelineNormal: [],
    timelineAttack: [],
    feedCount: 0,
};

let attackDistChart = null;
let timelineChart = null;

/* =========================================================
   Dashboard Page
   ========================================================= */

function initDashboard() {
    createAttackDistChart();
    createTimelineChart();
    connectSSE();
    updateHeaderTimestamp();
    setInterval(updateHeaderTimestamp, 1000);
}

function updateHeaderTimestamp() {
    const el = document.getElementById('header-timestamp');
    if (el) el.textContent = formatTimestamp(new Date());
}

/* --- Attack Distribution Donut --- */
function createAttackDistChart() {
    const ctx = document.getElementById('attackDistChart');
    if (!ctx) return;

    attackDistChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['DoS', 'Probe', 'R2L', 'U2R'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    COLORS.DoS,
                    COLORS.Probe,
                    COLORS.R2L,
                    COLORS.U2R,
                ],
                borderColor: 'rgba(10, 14, 39, 0.8)',
                borderWidth: 3,
                hoverBorderWidth: 0,
                hoverOffset: 8,
            }],
        },
        options: {
            cutout: '68%',
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (ctx) => ` ${ctx.label}: ${ctx.parsed} detections`,
                    },
                },
            },
            animation: {
                animateRotate: true,
                duration: 800,
            },
        },
    });

    updateAttackLegend();
}

function updateAttackLegend() {
    const container = document.getElementById('attack-legend');
    if (!container) return;

    const types = ['DoS', 'Probe', 'R2L', 'U2R'];
    container.innerHTML = types.map(t =>
        `<div class="legend-item">
            <span class="legend-dot" style="background:${COLORS[t]}"></span>
            <span>${t}: <strong id="legend-count-${t}">${dashboardState.attackCounts[t]}</strong></span>
        </div>`
    ).join('');
}

/* --- Traffic Timeline Line Chart --- */
function createTimelineChart() {
    const ctx = document.getElementById('timelineChart');
    if (!ctx) return;

    const chartCtx = ctx.getContext('2d');

    /* Gradient fills */
    const gradientNormal = chartCtx.createLinearGradient(0, 0, 0, 250);
    gradientNormal.addColorStop(0, 'rgba(0, 255, 136, 0.2)');
    gradientNormal.addColorStop(1, 'rgba(0, 255, 136, 0)');

    const gradientAttack = chartCtx.createLinearGradient(0, 0, 0, 250);
    gradientAttack.addColorStop(0, 'rgba(255, 51, 102, 0.2)');
    gradientAttack.addColorStop(1, 'rgba(255, 51, 102, 0)');

    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Normal',
                    data: [],
                    borderColor: COLORS.success,
                    backgroundColor: gradientNormal,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 5,
                    pointHoverBackgroundColor: COLORS.success,
                    borderWidth: 2,
                },
                {
                    label: 'Attack',
                    data: [],
                    borderColor: COLORS.danger,
                    backgroundColor: gradientAttack,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 5,
                    pointHoverBackgroundColor: COLORS.danger,
                    borderWidth: 2,
                },
            ],
        },
        options: {
            scales: {
                x: {
                    grid: { color: COLORS.gridLine },
                    ticks: { maxTicksLimit: 10, font: { size: 10 } },
                },
                y: {
                    beginAtZero: true,
                    grid: { color: COLORS.gridLine },
                    ticks: { stepSize: 1 },
                },
            },
            plugins: {
                legend: {
                    position: 'top',
                    align: 'end',
                },
            },
            interaction: {
                intersect: false,
                mode: 'index',
            },
            animation: { duration: 400 },
        },
    });
}

/* --- SSE Connection --- */
function connectSSE() {
    const source = new EventSource('/api/demo-feed');

    source.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleNewTraffic(data);
        } catch (e) {
            console.error('SSE parse error:', e);
        }
    };

    source.onerror = () => {
        console.warn('SSE disconnected, reconnecting in 5s...');
        source.close();
        setTimeout(connectSSE, 5000);
    };
}

function handleNewTraffic(data) {
    dashboardState.totalConnections++;
    dashboardState.feedCount++;

    const isAttack = data.prediction !== 'Normal' && data.attack_type !== 'Normal';

    if (isAttack) {
        dashboardState.threats++;
        const aType = data.attack_type;
        if (dashboardState.attackCounts[aType] !== undefined) {
            dashboardState.attackCounts[aType]++;
        }
    }

    /* Update stat counters */
    animateCounter(document.getElementById('stat-total'), dashboardState.totalConnections);
    animateCounter(document.getElementById('stat-threats'), dashboardState.threats);

    const rate = dashboardState.totalConnections > 0
        ? ((dashboardState.threats / dashboardState.totalConnections) * 100)
        : 0;
    const rateEl = document.getElementById('stat-rate');
    if (rateEl) rateEl.textContent = rate.toFixed(1) + '%';

    /* Update gauge */
    const gaugeFill = document.getElementById('gauge-fill');
    if (gaugeFill) {
        gaugeFill.setAttribute('stroke-dasharray', `${Math.min(rate, 100)}, 100`);
    }

    /* Update feed count badge */
    const feedCountEl = document.getElementById('feed-count');
    if (feedCountEl) feedCountEl.textContent = `${dashboardState.feedCount} events`;

    /* Add traffic entry to feed */
    addTrafficEntry(data);

    /* Update attack distribution chart */
    if (attackDistChart) {
        attackDistChart.data.datasets[0].data = [
            dashboardState.attackCounts.DoS,
            dashboardState.attackCounts.Probe,
            dashboardState.attackCounts.R2L,
            dashboardState.attackCounts.U2R,
        ];
        attackDistChart.update('none');
    }

    /* Update legend counts */
    for (const t of ['DoS', 'Probe', 'R2L', 'U2R']) {
        const el = document.getElementById(`legend-count-${t}`);
        if (el) el.textContent = dashboardState.attackCounts[t];
    }

    /* Update timeline */
    const timeLabel = formatTimestamp(new Date());
    dashboardState.timelineNormal.push(isAttack ? 0 : 1);
    dashboardState.timelineAttack.push(isAttack ? 1 : 0);

    if (dashboardState.timelineNormal.length > 60) {
        dashboardState.timelineNormal.shift();
        dashboardState.timelineAttack.shift();
    }

    if (timelineChart) {
        timelineChart.data.labels = dashboardState.timelineNormal.map((_, i) => {
            if (i % 5 === 0) return `t-${dashboardState.timelineNormal.length - i}`;
            return '';
        });
        timelineChart.data.datasets[0].data = [...dashboardState.timelineNormal];
        timelineChart.data.datasets[1].data = [...dashboardState.timelineAttack];
        timelineChart.update('none');
    }
}

/* --- Add Traffic Feed Entry --- */
function addTrafficEntry(data) {
    const feed = document.getElementById('traffic-feed');
    if (!feed) return;

    /* Remove empty state */
    const emptyState = document.getElementById('feed-empty-state');
    if (emptyState) emptyState.remove();

    const isAttack = data.prediction !== 'Normal' && data.attack_type !== 'Normal';

    const entry = document.createElement('div');
    entry.className = `traffic-entry ${isAttack ? 'attack' : 'normal'}`;
    entry.innerHTML = `
        <span class="entry-time">${formatTimestamp(data.timestamp || new Date())}</span>
        <span class="entry-ips">${data.src_ip}<span class="arrow">→</span>${data.dst_ip}</span>
        <span class="entry-protocol">${data.protocol || 'tcp'}</span>
        <span class="badge ${getAttackBadgeClass(data.attack_type)}">${data.attack_type || 'Normal'}</span>
    `;

    feed.prepend(entry);

    /* Keep max 50 entries */
    while (feed.children.length > 50) {
        const last = feed.lastElementChild;
        if (last) {
            last.style.opacity = '0';
            setTimeout(() => last.remove(), 300);
        }
    }
}

/* =========================================================
   Models Page
   ========================================================= */

async function initModelsPage() {
    updateHeaderTimestamp();
    setInterval(updateHeaderTimestamp, 1000);

    try {
        const res = await fetch('/api/metrics');
        const metrics = await res.json();
        populateComparisonTable(metrics);
        createRadarChart(metrics);
        createTrainingTimeChart(metrics);
        createPerClassChart(metrics);
    } catch (e) {
        console.error('Failed to load metrics:', e);
    }
}

function populateComparisonTable(metrics) {
    const tbody = document.getElementById('comparison-tbody');
    if (!tbody) return;

    const models = Object.keys(metrics);
    const metricKeys = ['accuracy', 'precision', 'recall', 'f1_score', 'training_time'];

    /* Find best values per metric */
    const bestVals = {};
    metricKeys.forEach(key => {
        if (key === 'training_time') {
            bestVals[key] = Math.min(...models.map(m => metrics[m][key] || 0));
        } else {
            bestVals[key] = Math.max(...models.map(m => metrics[m][key] || 0));
        }
    });

    const modelColors = { 'Random Forest': COLORS.rf, 'XGBoost': COLORS.xgb, 'LSTM': COLORS.lstm };

    tbody.innerHTML = models.map(model => {
        const m = metrics[model];
        return `<tr>
            <td class="model-name" style="color: ${modelColors[model] || COLORS.cyan}">${model}</td>
            ${metricKeys.map(key => {
                const val = m[key] || 0;
                const isBest = Math.abs(val - bestVals[key]) < 0.0001;
                const display = key === 'training_time' ? val.toFixed(1) + 's' : (val * 100).toFixed(1) + '%';
                return `<td class="${isBest ? 'best-value' : ''}">${display}</td>`;
            }).join('')}
        </tr>`;
    }).join('');
}

function createRadarChart(metrics) {
    const ctx = document.getElementById('radarChart');
    if (!ctx) return;

    const models = Object.keys(metrics);
    const metricLabels = ['Accuracy', 'Precision', 'Recall', 'F1 Score'];
    const metricKeys = ['accuracy', 'precision', 'recall', 'f1_score'];
    const modelColors = [COLORS.rf, COLORS.xgb, COLORS.lstm];

    new Chart(ctx, {
        type: 'radar',
        data: {
            labels: metricLabels,
            datasets: models.map((model, i) => ({
                label: model,
                data: metricKeys.map(k => (metrics[model][k] || 0) * 100),
                borderColor: modelColors[i],
                backgroundColor: modelColors[i] + '15',
                borderWidth: 2,
                pointBackgroundColor: modelColors[i],
                pointBorderColor: modelColors[i],
                pointRadius: 4,
                pointHoverRadius: 6,
            })),
        },
        options: {
            scales: {
                r: {
                    beginAtZero: false,
                    min: 90,
                    max: 100,
                    ticks: {
                        stepSize: 2,
                        font: { size: 10 },
                        backdropColor: 'transparent',
                    },
                    grid: { color: COLORS.gridLine },
                    angleLines: { color: COLORS.gridLine },
                    pointLabels: {
                        font: { size: 12, weight: '500' },
                        color: COLORS.textSecondary,
                    },
                },
            },
            plugins: {
                legend: {
                    position: 'bottom',
                },
                tooltip: {
                    callbacks: {
                        label: (ctx) => ` ${ctx.dataset.label}: ${ctx.parsed.r.toFixed(1)}%`,
                    },
                },
            },
        },
    });
}

function createTrainingTimeChart(metrics) {
    const ctx = document.getElementById('trainingTimeChart');
    if (!ctx) return;

    const models = Object.keys(metrics);
    const modelColors = [COLORS.rf, COLORS.xgb, COLORS.lstm];

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: models,
            datasets: [{
                label: 'Training Time (seconds)',
                data: models.map(m => metrics[m].training_time || 0),
                backgroundColor: modelColors.map(c => c + '40'),
                borderColor: modelColors,
                borderWidth: 2,
                borderRadius: 8,
                barPercentage: 0.5,
            }],
        },
        options: {
            indexAxis: 'y',
            scales: {
                x: {
                    grid: { color: COLORS.gridLine },
                    title: { display: true, text: 'Seconds', color: COLORS.textMuted, font: { size: 11 } },
                },
                y: {
                    grid: { display: false },
                },
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (ctx) => ` ${ctx.parsed.x.toFixed(1)}s`,
                    },
                },
            },
        },
    });
}

function createPerClassChart(metrics) {
    const ctx = document.getElementById('perClassChart');
    if (!ctx) return;

    const models = Object.keys(metrics);
    const classes = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'];
    const modelColors = [COLORS.rf, COLORS.xgb, COLORS.lstm];

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: classes,
            datasets: models.map((model, i) => ({
                label: model,
                data: classes.map(cls => {
                    const pc = metrics[model]?.per_class?.[cls];
                    return pc ? (pc.f1_score * 100) : 0;
                }),
                backgroundColor: modelColors[i] + '50',
                borderColor: modelColors[i],
                borderWidth: 2,
                borderRadius: 6,
            })),
        },
        options: {
            scales: {
                x: {
                    grid: { display: false },
                },
                y: {
                    beginAtZero: false,
                    min: 80,
                    max: 100,
                    grid: { color: COLORS.gridLine },
                    title: { display: true, text: 'F1 Score (%)', color: COLORS.textMuted, font: { size: 11 } },
                },
            },
            plugins: {
                legend: {
                    position: 'top',
                    align: 'end',
                },
                tooltip: {
                    callbacks: {
                        label: (ctx) => ` ${ctx.dataset.label}: ${ctx.parsed.y.toFixed(1)}%`,
                    },
                },
            },
        },
    });
}

/* =========================================================
   Alerts Page
   ========================================================= */

let alertsData = [];
let currentFilter = 'all';

async function initAlertsPage() {
    updateHeaderTimestamp();
    setInterval(updateHeaderTimestamp, 1000);

    setupFilters();
    await refreshAlerts();
    setInterval(refreshAlerts, 5000);
}

function setupFilters() {
    const buttons = document.querySelectorAll('.filter-btn');
    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            buttons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.dataset.filter;
            renderAlertsTable();
        });
    });
}

async function refreshAlerts() {
    try {
        const res = await fetch('/api/traffic');
        alertsData = await res.json();
        renderAlertsTable();
    } catch (e) {
        console.error('Failed to refresh alerts:', e);
    }
}

function renderAlertsTable() {
    const tbody = document.getElementById('alerts-tbody');
    const emptyState = document.getElementById('alerts-empty-state');
    const countBadge = document.getElementById('alerts-count');
    if (!tbody) return;

    /* Filter for attacks only, then by type */
    let threats = alertsData.filter(d => d.attack_type !== 'Normal' && d.prediction !== 'Normal');
    if (currentFilter !== 'all') {
        threats = threats.filter(d => d.attack_type === currentFilter);
    }

    if (countBadge) countBadge.textContent = `${threats.length} threats`;

    if (threats.length === 0) {
        tbody.innerHTML = '';
        if (emptyState) emptyState.classList.add('visible');
        return;
    }

    if (emptyState) emptyState.classList.remove('visible');

    /* Show most recent first */
    const sorted = [...threats].reverse();

    tbody.innerHTML = sorted.map(d => {
        const confPercent = ((d.confidence || 0) * 100).toFixed(1);
        return `<tr>
            <td>${d.timestamp || '--'}</td>
            <td>${d.src_ip || '--'}</td>
            <td>${d.dst_ip || '--'}</td>
            <td style="text-transform:uppercase">${d.protocol || '--'}</td>
            <td><span class="badge ${getAttackBadgeClass(d.attack_type)}">${d.attack_type}</span></td>
            <td>
                <div class="confidence-bar">
                    <span>${confPercent}%</span>
                    <div class="confidence-fill" style="width:${confPercent * 0.8}px"></div>
                </div>
            </td>
            <td>XGBoost</td>
        </tr>`;
    }).join('');
}

/* =========================================================
   Mobile Menu Toggle
   ========================================================= */
function initMobileMenu() {
    const toggle = document.getElementById('mobile-menu-toggle');
    const sidebar = document.querySelector('.sidebar');
    if (!toggle || !sidebar) return;

    /* Create overlay */
    let overlay = document.querySelector('.sidebar-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.className = 'sidebar-overlay';
        document.body.appendChild(overlay);
    }

    toggle.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        overlay.classList.toggle('active');
    });

    overlay.addEventListener('click', () => {
        sidebar.classList.remove('open');
        overlay.classList.remove('active');
    });
}

/* =========================================================
   Page Detection & Initialization
   ========================================================= */
document.addEventListener('DOMContentLoaded', () => {
    initMobileMenu();

    const path = window.location.pathname;
    if (path === '/' || path === '') {
        initDashboard();
    } else if (path === '/models') {
        initModelsPage();
    } else if (path === '/alerts') {
        initAlertsPage();
    }
});
