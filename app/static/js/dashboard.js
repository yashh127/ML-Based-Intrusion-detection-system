/* =========================================================
   NetShield IDS — Dashboard JavaScript
   Chart.js configuration, SSE real-time feed, counters
   ========================================================= */

/* --- Theme Toggle --- */
function initThemeToggle() {
    const saved = localStorage.getItem('ids-theme') || 'dark';
    applyTheme(saved);

    const btn = document.getElementById('theme-toggle');
    if (btn) {
        btn.addEventListener('click', () => {
            const current = document.documentElement.getAttribute('data-theme');
            const next = current === 'light' ? 'dark' : 'light';
            applyTheme(next);
            localStorage.setItem('ids-theme', next);
        });
    }
}

function applyTheme(theme) {
    if (theme === 'light') {
        document.documentElement.setAttribute('data-theme', 'light');
    } else {
        document.documentElement.removeAttribute('data-theme');
    }

    const icon = document.getElementById('theme-icon');
    const label = document.getElementById('theme-label');
    if (icon) icon.textContent = theme === 'light' ? '☀️' : '🌙';
    if (label) label.textContent = theme === 'light' ? 'Light' : 'Dark';

    /* Update Chart.js defaults for the new theme */
    if (typeof Chart !== 'undefined') {
        const textColor = theme === 'light' ? '#475569' : '#94a3b8';
        const gridColor = theme === 'light' ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.04)';
        Chart.defaults.color = textColor;
        Chart.defaults.borderColor = gridColor;
    }
}

/* Apply theme immediately to prevent flash */
(function() {
    const saved = localStorage.getItem('ids-theme') || 'dark';
    if (saved === 'light') {
        document.documentElement.setAttribute('data-theme', 'light');
    }
})();

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
    /* Handled by the live clock now */
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
            /* Trigger toast for attacks */
            if (window.triggerAttackToast) {
                window.triggerAttackToast(data);
            }
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
    initThemeToggle();

    const path = window.location.pathname;
    if (path === '/' || path === '') {
        initDashboard();
    } else if (path === '/models') {
        initModelsPage();
    } else if (path === '/alerts') {
        initAlertsPage();
    }

    /* Initialize futuristic effects */
    initParticleNetwork();
});

/* =========================================================
   Particle Network Background
   ========================================================= */
function initParticleNetwork() {
    const canvas = document.getElementById('particle-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let particles = [];
    let animId;
    const MAX_PARTICLES = 60;
    const CONNECT_DIST = 150;

    function resize() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    class Particle {
        constructor() {
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
            this.vx = (Math.random() - 0.5) * 0.6;
            this.vy = (Math.random() - 0.5) * 0.6;
            this.radius = Math.random() * 2 + 1;
            this.opacity = Math.random() * 0.5 + 0.2;
        }

        update() {
            this.x += this.vx;
            this.y += this.vy;

            if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
            if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
        }

        draw() {
            const isLight = document.documentElement.getAttribute('data-theme') === 'light';
            const color = isLight ? '8, 145, 178' : '0, 212, 255';
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${color}, ${this.opacity})`;
            ctx.fill();
        }
    }

    // Create particles
    for (let i = 0; i < MAX_PARTICLES; i++) {
        particles.push(new Particle());
    }

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        const isLight = document.documentElement.getAttribute('data-theme') === 'light';
        const lineColor = isLight ? '8, 145, 178' : '0, 212, 255';

        // Draw connections
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < CONNECT_DIST) {
                    const opacity = (1 - dist / CONNECT_DIST) * 0.15;
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(${lineColor}, ${opacity})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        }

        // Update and draw particles
        particles.forEach(p => {
            p.update();
            p.draw();
        });

        animId = requestAnimationFrame(animate);
    }

    animate();
}

/* =========================================================
   Toast Notification System
   ========================================================= */
function showToast(title, message, type = 'danger') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const icons = {
        danger: '🚨',
        warning: '⚠️',
        success: '✅',
        info: 'ℹ️',
    };

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.style.borderLeftColor = type === 'danger' ? 'var(--accent-danger)'
        : type === 'warning' ? 'var(--accent-warning)'
        : type === 'success' ? 'var(--accent-success)'
        : 'var(--accent-cyan)';

    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || '🔔'}</span>
        <div class="toast-body">
            <div class="toast-title">${title}</div>
            <div class="toast-msg">${message}</div>
        </div>
        <button class="toast-close" onclick="dismissToast(this)">✕</button>
    `;

    container.appendChild(toast);

    // Auto-dismiss after 4 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.classList.add('toast-out');
            setTimeout(() => toast.remove(), 400);
        }
    }, 4000);

    // Keep max 3 toasts
    while (container.children.length > 3) {
        container.firstChild.remove();
    }
}

function dismissToast(btn) {
    const toast = btn.closest('.toast');
    toast.classList.add('toast-out');
    setTimeout(() => toast.remove(), 400);
}

/* Hook toast into the traffic feed — show alerts for attacks */
const _origAddTrafficEntry = typeof addTrafficEntry === 'function' ? addTrafficEntry : null;
if (_origAddTrafficEntry) {
    const originalAdd = addTrafficEntry;
    // We'll patch this from the SSE handler instead
}

/* Patch SSE to trigger toasts on attacks */
(function() {
    const origES = window.EventSource;
    if (!origES) return;

    const _origAddEvent = EventSource.prototype.addEventListener;
    // Instead, we'll use a global hook
    window._toastAttackCount = 0;
    window._lastToastTime = 0;

    window.triggerAttackToast = function(data) {
        const now = Date.now();
        // Only show toast every 8 seconds max to avoid spam
        if (now - window._lastToastTime < 8000) return;
        window._lastToastTime = now;

        if (data.attack_type && data.attack_type !== 'Normal') {
            const typeMap = { DoS: 'danger', Probe: 'warning', R2L: 'danger', U2R: 'danger' };
            showToast(
                `${data.attack_type} Attack Detected`,
                `${data.src_ip} → ${data.dst_ip} via ${data.protocol} (${Math.round(data.confidence * 100)}% confidence)`,
                typeMap[data.attack_type] || 'warning'
            );
        }
    };
})();

/* =========================================================
   Enhanced Features v2.1
   ========================================================= */

/* --- Keyboard Shortcuts --- */
(function initKeyboardShortcuts() {
    const overlay = document.getElementById('shortcuts-overlay');
    const closeBtn = document.getElementById('shortcuts-close');
    const hintBtn = document.getElementById('shortcut-hint-btn');

    function toggleShortcuts(show) {
        if (overlay) overlay.classList.toggle('active', show);
    }

    if (closeBtn) closeBtn.addEventListener('click', () => toggleShortcuts(false));
    if (hintBtn) hintBtn.addEventListener('click', () => toggleShortcuts(true));
    if (overlay) overlay.addEventListener('click', (e) => {
        if (e.target === overlay) toggleShortcuts(false);
    });

    document.addEventListener('keydown', (e) => {
        // Don't trigger in inputs
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

        switch (e.key) {
            case '1': window.location.href = '/'; break;
            case '2': window.location.href = '/models'; break;
            case '3': window.location.href = '/alerts'; break;
            case 't':
            case 'T':
                document.getElementById('theme-toggle')?.click();
                break;
            case 'f':
            case 'F':
                toggleFullscreen();
                break;
            case 'e':
            case 'E':
                exportAlertsCSV();
                break;
            case 's':
            case 'S':
                toggleAlertSound();
                break;
            case '?':
                toggleShortcuts(true);
                break;
            case 'Escape':
                toggleShortcuts(false);
                break;
        }
    });
})();

/* --- Live Clock --- */
(function initLiveClock() {
    const clockEl = document.getElementById('header-clock');
    if (!clockEl) return;

    function updateClock() {
        const now = new Date();
        clockEl.textContent = now.toLocaleTimeString('en-US', { hour12: false });
    }

    updateClock();
    setInterval(updateClock, 1000);
})();

/* --- Uptime Counter --- */
(function initUptime() {
    const el = document.getElementById('uptime-counter');
    if (!el) return;

    const startTime = Date.now();

    function updateUptime() {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const h = String(Math.floor(elapsed / 3600)).padStart(2, '0');
        const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
        const s = String(elapsed % 60).padStart(2, '0');
        el.textContent = `${h}:${m}:${s}`;
    }

    setInterval(updateUptime, 1000);
})();

/* --- 3D Holographic Tilt on Stat Cards --- */
(function initHoloTilt() {
    document.querySelectorAll('.stats-grid .glass-card').forEach(card => {
        card.classList.add('holo-tilt');

        // Add shine overlay
        const shine = document.createElement('div');
        shine.className = 'holo-shine';
        card.appendChild(shine);

        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = ((e.clientX - rect.left) / rect.width) * 100;
            const y = ((e.clientY - rect.top) / rect.height) * 100;

            const rotateX = ((y - 50) / 50) * -6;
            const rotateY = ((x - 50) / 50) * 6;

            card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale(1.02)`;
            card.style.setProperty('--mouse-x', x + '%');
            card.style.setProperty('--mouse-y', y + '%');
        });

        card.addEventListener('mouseleave', () => {
            card.style.transform = 'perspective(1000px) rotateX(0) rotateY(0) scale(1)';
        });
    });
})();

/* --- Status Bar Live Updates --- */
(function initStatusBar() {
    let ppsCounter = 0;
    let threatCounter = 0;

    const ppsEl = document.getElementById('status-pps');
    const threatsEl = document.getElementById('status-threats');

    // Hook into traffic feed to update counters
    const origHandle = window.handleNewTraffic;
    if (typeof origHandle === 'function') {
        window.handleNewTraffic = function(data) {
            origHandle(data);
            ppsCounter++;
            if (data.prediction !== 'Normal' && data.attack_type !== 'Normal') {
                threatCounter++;
            }
            if (threatsEl) threatsEl.textContent = threatCounter;
        };
    }

    // Update PPS every second
    setInterval(() => {
        if (ppsEl) ppsEl.textContent = ppsCounter;
        ppsCounter = 0;
    }, 1000);
})();

/* --- Typing Animation on Page Titles --- */
(function initTypingEffect() {
    const title = document.querySelector('.page-title');
    if (!title) return;

    const text = title.textContent;
    title.textContent = '';
    title.classList.add('typing-cursor');

    let i = 0;
    function typeChar() {
        if (i < text.length) {
            title.textContent += text[i];
            i++;
            setTimeout(typeChar, 50 + Math.random() * 30);
        } else {
            // Remove cursor after typing is done
            setTimeout(() => title.classList.remove('typing-cursor'), 1500);
        }
    }

    setTimeout(typeChar, 300);
})();

/* =========================================================
   Showcase Features v2.2
   ========================================================= */

/* --- Fullscreen Toggle --- */
function toggleFullscreen() {
    const btn = document.getElementById('fullscreen-toggle');
    const icon = document.getElementById('fullscreen-icon');

    if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen().then(() => {
            document.body.classList.add('fullscreen-mode');
            if (icon) icon.textContent = '⛶';
            showToast('Fullscreen', 'Press F or Esc to exit', 'info');
        }).catch(() => {});
    } else {
        document.exitFullscreen().then(() => {
            document.body.classList.remove('fullscreen-mode');
            if (icon) icon.textContent = '⛶';
        }).catch(() => {});
    }
}

document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement) {
        document.body.classList.remove('fullscreen-mode');
    }
});

if (document.getElementById('fullscreen-toggle')) {
    document.getElementById('fullscreen-toggle').addEventListener('click', toggleFullscreen);
}

/* --- Alert Sound Toggle --- */
let alertSoundEnabled = false;
let alertAudioCtx = null;

function toggleAlertSound() {
    alertSoundEnabled = !alertSoundEnabled;
    const btn = document.getElementById('sound-toggle');
    const icon = document.getElementById('sound-icon');
    const statusSound = document.getElementById('status-sound');

    if (btn) btn.classList.toggle('active', alertSoundEnabled);
    if (icon) icon.textContent = alertSoundEnabled ? '🔊' : '🔇';
    if (statusSound) {
        statusSound.textContent = alertSoundEnabled ? 'ON' : 'OFF';
        statusSound.classList.toggle('status-success', alertSoundEnabled);
    }

    showToast('Sound Alerts', alertSoundEnabled ? 'Alert sounds enabled' : 'Alert sounds disabled', 'info');
}

function playAlertBeep() {
    if (!alertSoundEnabled) return;
    try {
        if (!alertAudioCtx) alertAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const ctx = alertAudioCtx;
        const t = ctx.currentTime;

        /* --- Cyberpunk 3-tone alert --- */

        /* Tone 1: Rising sweep (sci-fi radar ping) */
        const osc1 = ctx.createOscillator();
        const gain1 = ctx.createGain();
        osc1.connect(gain1);
        gain1.connect(ctx.destination);
        osc1.type = 'sine';
        osc1.frequency.setValueAtTime(400, t);
        osc1.frequency.exponentialRampToValueAtTime(1200, t + 0.15);
        gain1.gain.setValueAtTime(0.18, t);
        gain1.gain.exponentialRampToValueAtTime(0.001, t + 0.2);
        osc1.start(t);
        osc1.stop(t + 0.2);

        /* Tone 2: Sharp staccato ping */
        const osc2 = ctx.createOscillator();
        const gain2 = ctx.createGain();
        osc2.connect(gain2);
        gain2.connect(ctx.destination);
        osc2.type = 'square';
        osc2.frequency.value = 1800;
        gain2.gain.setValueAtTime(0, t + 0.22);
        gain2.gain.linearRampToValueAtTime(0.1, t + 0.23);
        gain2.gain.exponentialRampToValueAtTime(0.001, t + 0.33);
        osc2.start(t + 0.22);
        osc2.stop(t + 0.35);

        /* Tone 3: Lower confirmation tone */
        const osc3 = ctx.createOscillator();
        const gain3 = ctx.createGain();
        osc3.connect(gain3);
        gain3.connect(ctx.destination);
        osc3.type = 'triangle';
        osc3.frequency.value = 600;
        gain3.gain.setValueAtTime(0, t + 0.36);
        gain3.gain.linearRampToValueAtTime(0.12, t + 0.37);
        gain3.gain.exponentialRampToValueAtTime(0.001, t + 0.55);
        osc3.start(t + 0.36);
        osc3.stop(t + 0.55);

    } catch (e) { /* ignore audio errors */ }
}

if (document.getElementById('sound-toggle')) {
    document.getElementById('sound-toggle').addEventListener('click', toggleAlertSound);
}

/* Patch triggerAttackToast to also play sound */
const _origTriggerToast = window.triggerAttackToast;
window.triggerAttackToast = function(data) {
    if (_origTriggerToast) _origTriggerToast(data);
    if (data.attack_type && data.attack_type !== 'Normal') {
        playAlertBeep();
    }
};

/* --- Export Alerts to CSV --- */
function exportAlertsCSV() {
    const rows = document.querySelectorAll('#alerts-table tbody tr, .traffic-entry');
    if (rows.length === 0) {
        showToast('Export', 'No alert data to export yet', 'warning');
        return;
    }

    let csv = 'Timestamp,Source IP,Destination IP,Protocol,Attack Type,Confidence\n';

    // Try to export from the stored traffic data
    if (window._alertHistory && window._alertHistory.length > 0) {
        window._alertHistory.forEach(d => {
            csv += `${d.timestamp || ''},${d.src_ip || ''},${d.dst_ip || ''},${d.protocol || ''},${d.attack_type || ''},${d.confidence || ''}\n`;
        });
    } else {
        // Fallback: scrape from DOM
        rows.forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length >= 5) {
                const vals = Array.from(cells).map(c => c.textContent.trim());
                csv += vals.join(',') + '\n';
            }
        });
    }

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netshield_alerts_${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);

    showToast('Export Complete', 'Alerts downloaded as CSV', 'success');
}

if (document.getElementById('export-btn')) {
    document.getElementById('export-btn').addEventListener('click', exportAlertsCSV);
}

/* Store alert history for export */
window._alertHistory = [];
const _origHandleTraffic2 = window.handleNewTraffic;
if (typeof _origHandleTraffic2 === 'function') {
    window.handleNewTraffic = function(data) {
        _origHandleTraffic2(data);
        if (data.attack_type && data.attack_type !== 'Normal') {
            window._alertHistory.push(data);
            if (window._alertHistory.length > 500) window._alertHistory.shift();
        }
    };
}

/* --- Live Threat Gauge --- */
(function initThreatGauge() {
    let totalCount = 0;
    let threatCount = 0;

    const fill = document.getElementById('threat-gauge-fill');
    const pct = document.getElementById('threat-gauge-pct');

    setInterval(() => {
        if (!fill || !pct) return;
        // Use dashboard state if available
        if (typeof dashboardState !== 'undefined') {
            totalCount = dashboardState.totalConnections || 1;
            threatCount = dashboardState.threatCount || 0;
        }

        const percent = totalCount > 0 ? Math.round((threatCount / totalCount) * 100) : 0;
        fill.style.width = Math.min(percent, 100) + '%';
        pct.textContent = percent + '%';

        // Change shadow color based on severity
        if (percent > 50) {
            fill.style.boxShadow = '0 0 10px rgba(255, 51, 102, 0.5)';
        } else if (percent > 25) {
            fill.style.boxShadow = '0 0 10px rgba(255, 170, 0, 0.4)';
        } else {
            fill.style.boxShadow = '0 0 10px rgba(0, 255, 136, 0.3)';
        }
    }, 2000);
})();
