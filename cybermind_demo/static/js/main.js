/**
 * CyberMind IDS — static/js/main.js
 * ====================================
 * Layer 1: Frontend JavaScript
 *
 * Key features implemented here:
 *  1. setInterval loop — polls /get_latest_traffic every 2 seconds
 *  2. Chart.js — updateChart() renders a live bar chart of traffic labels
 *  3. Async fetch — startScan() never freezes the page (async/await)
 *  4. Active-voice UI — "CyberMind is scanning…" not "Analysis is being performed"
 *  5. SQLite log viewer — loadLogs() fetches /logs and renders the table
 */

'use strict';

// =============================================================================
// Chart.js instances (created once, updated on each poll)
// =============================================================================

let barChart   = null;   // #threatChart   — bar chart (as per professor's spec)
let donutChart = null;   // #donutChart    — doughnut variant

// Colour palette keyed by label name
const LABEL_COLORS = {
  safe:          { bg: '#22c55e44', border: '#22c55e' },
  brute_force:   { bg: '#ef444444', border: '#ef4444' },
  port_scan:     { bg: '#f9731644', border: '#f97316' },
  ddos:          { bg: '#f43f5e44', border: '#f43f5e' },
  sql_injection: { bg: '#a855f744', border: '#a855f7' },
  malware_c2:    { bg: '#facc1544', border: '#facc15' },
};

function _colorFor(label, type) {
  const c = LABEL_COLORS[label];
  if (c) return type === 'bg' ? c.bg : c.border;
  return type === 'bg' ? '#71717a44' : '#71717a';
}

/**
 * updateChart(labels, counts)
 * Creates or updates both the bar chart (#threatChart) and doughnut (#donutChart)
 * with fresh data from /get_latest_traffic.
 *
 * Called automatically by the 2-second setInterval loop.
 */
function updateChart(labels, counts) {
  const bgColors     = labels.map(l => _colorFor(l, 'bg'));
  const borderColors = labels.map(l => _colorFor(l, 'border'));

  // ── Bar chart (#threatChart) — as specified by professor ─────────────────
  const barCtx = document.getElementById('threatChart')?.getContext('2d');
  if (barCtx) {
    if (barChart) {
      barChart.data.labels                        = labels;
      barChart.data.datasets[0].data             = counts;
      barChart.data.datasets[0].backgroundColor  = bgColors;
      barChart.data.datasets[0].borderColor      = borderColors;
      barChart.update('active');
    } else {
      barChart = new Chart(barCtx, {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label:           'Packets classified',
            data:            counts,
            backgroundColor: bgColors,
            borderColor:     borderColors,
            borderWidth:     2,
            borderRadius:    6,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: ctx => ` ${ctx.parsed.y} packets  (${ctx.label.replace(/_/g,' ')})`,
              },
            },
          },
          scales: {
            x: {
              ticks: { color: '#a1a1aa', font: { family: 'Inter', size: 11 } },
              grid:  { color: '#27272a' },
            },
            y: {
              ticks: { color: '#a1a1aa', font: { family: 'Inter', size: 11 } },
              grid:  { color: '#27272a' },
              beginAtZero: true,
            },
          },
        },
      });
    }
    document.getElementById('chart-empty')?.classList.add('hidden');
  }

  // ── Doughnut chart (#donutChart) ─────────────────────────────────────────
  const donutCtx = document.getElementById('donutChart')?.getContext('2d');
  if (donutCtx) {
    if (donutChart) {
      donutChart.data.labels                    = labels;
      donutChart.data.datasets[0].data          = counts;
      donutChart.data.datasets[0].backgroundColor = bgColors;
      donutChart.data.datasets[0].borderColor   = borderColors;
      donutChart.update('active');
    } else {
      donutChart = new Chart(donutCtx, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data:            counts,
            backgroundColor: bgColors,
            borderColor:     borderColors,
            borderWidth:     2,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '65%',
          plugins: {
            legend: {
              position: 'right',
              labels: { color: '#a1a1aa', font: { family: 'Inter', size: 11 }, padding: 14 },
            },
          },
        },
      });
    }
    document.getElementById('donut-empty')?.classList.add('hidden');
  }
}


// =============================================================================
// /get_latest_traffic — 2-second polling loop
//
// This is exactly the pattern the professor described:
//   setInterval(async () => { const response = await fetch('/get_latest_traffic'); ... }, 2000);
// =============================================================================

let _lastPacketCount = 0;

setInterval(async () => {
  try {
    // Flash the refresh indicator in the sidebar
    const dot = document.getElementById('refresh-dot');
    if (dot) { dot.style.opacity = '1'; setTimeout(() => dot.style.opacity = '0', 400); }

    const response = await fetch('/get_latest_traffic');
    if (!response.ok) return;
    const data = await response.json();

    // ── Update live stat counters ─────────────────────────────────────────────
    const statScans   = document.getElementById('stat-scans');
    const statThreats = document.getElementById('stat-threats');
    const statPackets = document.getElementById('stat-packets');
    if (statScans)   statScans.textContent   = data.total_scans   ?? '0';
    if (statThreats) statThreats.textContent = data.threats_today ?? '0';
    if (statPackets) statPackets.textContent = data.traffic_count ?? '0';

    // ── Update Chart.js with new Scapy data ──────────────────────────────────
    if (data.traffic_labels?.length) {
      updateChart(data.traffic_labels, data.traffic_counts);
      _lastPacketCount = data.traffic_count;
    }

    // ── Update recent activity table ──────────────────────────────────────────
    if (data.recent_logs?.length) {
      renderActivityTable(data.recent_logs);
    }

  } catch (_err) {
    // Silently ignore network errors (Flask may still be starting up)
  }
}, 2000);   // ← 2-second interval as specified


// =============================================================================
// Activity table renderer
// =============================================================================

const SEV_BADGE = {
  critical: 'badge-critical',
  medium:   'badge-medium',
  low:      'badge-low',
};

function renderActivityTable(logs) {
  const table = document.getElementById('activity-table');
  const tbody = document.getElementById('activity-body');
  const empty = document.getElementById('activity-empty');

  if (!logs.length) return;
  if (empty) empty.classList.add('hidden');
  if (table) table.classList.remove('hidden');
  if (!tbody) return;

  tbody.innerHTML = logs.map(row => {
    const ts    = row.timestamp ? new Date(row.timestamp).toLocaleTimeString() : '—';
    const label = (row.label || '').replace(/_/g, ' ');
    const badgeCls = SEV_BADGE[row.severity] || 'badge-low';
    const threat   = row.threat_detected
      ? '<span class="badge badge-critical">THREAT</span>'
      : '<span class="badge badge-low">SAFE</span>';

    return `<tr>
      <td class="mono dim">${ts}</td>
      <td><span class="label-text">${label}</span></td>
      <td class="mono">${row.confidence}%</td>
      <td class="mono">${row.packet_count}</td>
      <td><span class="mode-tag">${row.capture_mode}</span></td>
      <td>${threat}</td>
    </tr>`;
  }).join('');
}


// =============================================================================
// Navigation
// =============================================================================

document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    navigateTo(link.dataset.screen);
    if (link.dataset.screen === 'logs') loadLogs();
  });
});

const SCREEN_TITLES = {
  dashboard: ['Dashboard',     'Live network threat intelligence — updates every 2 seconds'],
  scan:      ['Live Scan',     'CyberMind is ready to capture and classify network packets'],
  analyze:   ['Text Analyzer', 'CyberMind checks your log entries against known attack signatures'],
  logs:      ['Scan Logs',     'CyberMind stores every scan result in a local SQLite database'],
};

function navigateTo(screenId) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));

  document.getElementById(`screen-${screenId}`)?.classList.add('active');
  document.querySelector(`[data-screen="${screenId}"]`)?.classList.add('active');

  const [title, sub] = SCREEN_TITLES[screenId] || ['CyberMind', ''];
  document.getElementById('page-title').textContent = title;
  document.getElementById('page-sub').textContent   = sub;
}


// =============================================================================
// Severity & result rendering helpers
// =============================================================================

const SEV_STYLES = {
  critical: { header: 'sev-critical', badge: 'badge-critical', icon: 'icon-critical', emoji: '🚨' },
  medium:   { header: 'sev-medium',   badge: 'badge-medium',   icon: 'icon-medium',   emoji: '⚠️' },
  low:      { header: 'sev-low',      badge: 'badge-low',      icon: 'icon-low',      emoji: '✅' },
};

const BAR_FILL = {
  safe:          'fill-safe',
  brute_force:   'fill-brute_force',
  port_scan:     'fill-port_scan',
  ddos:          'fill-ddos',
  sql_injection: 'fill-sql_injection',
  malware_c2:    'fill-malware_c2',
};

function buildResultCard(result) {
  const s       = SEV_STYLES[result.severity] || SEV_STYLES.low;
  const confPct = Math.round((result.confidence || 0) * 100);
  const modeStr = result.capture_mode === 'live' ? '📡 live capture' :
                  result.capture_mode === 'simulated' ? '🔬 simulated' : '';
  const tsStr   = result.timestamp ? new Date(result.timestamp).toLocaleTimeString() : '';

  const breakdownHTML = Object.entries(result.breakdown || {})
    .sort(([, a], [, b]) => b - a)
    .map(([lbl, pct]) => `
      <div class="breakdown-bar-row">
        <div class="label-row">
          <span>${lbl.replace(/_/g,' ')}</span>
          <span class="mono dim">${pct.toFixed(1)}%</span>
        </div>
        <div class="track"><div class="fill ${BAR_FILL[lbl]||''}" style="width:${pct}%"></div></div>
      </div>`).join('');

  return `
    <div class="result-header ${s.header}" style="border-bottom:1px solid var(--border)">
      <div class="result-icon ${s.icon}">${s.emoji}</div>
      <div style="flex:1">
        <div class="result-verdict">${result.verdict || result.label}</div>
        <div class="result-meta">
          <span class="badge ${s.badge}">${(result.severity||'low').toUpperCase()}</span>
          <span class="mono">${confPct}% confidence</span>
          ${modeStr ? `<span class="mono dim">${modeStr}</span>` : ''}
        </div>
      </div>
      <div style="text-align:right;flex-shrink:0">
        <div style="font-size:32px;font-weight:900;font-family:'JetBrains Mono',monospace;
                    color:${result.threat_detected?'var(--red)':'var(--green)'}">${confPct}%</div>
        <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:1px">confidence</div>
      </div>
    </div>
    <div class="result-body">
      <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;font-weight:700;margin-bottom:10px">
        Traffic Breakdown
      </div>
      ${breakdownHTML}
    </div>
    <div class="result-footer">
      <span>packets: <strong>${result.packet_count ?? '—'}</strong></span>
      ${modeStr ? `<span>mode: <strong>${result.capture_mode}</strong></span>` : ''}
      ${tsStr   ? `<span>time: <strong>${tsStr}</strong></span>` : ''}
      <span style="margin-left:auto;color:var(--dim);font-size:10px">
        Saved to cybermind_logs.db ✓
      </span>
    </div>`;
}

function showResult(containerEl, result) {
  if (!containerEl) return;
  containerEl.innerHTML = buildResultCard(result);
  containerEl.classList.remove('hidden');
  containerEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}


// =============================================================================
// LIVE SCAN
// =============================================================================

let _pollTimer = null;

// Active-voice phase labels (as per professor's UI guidance)
const PHASE_MSGS = {
  starting:    'CyberMind is preparing the scanner…',
  capturing:   'CyberMind is capturing packets from your network…',
  classifying: 'CyberMind is running the Random Forest classifier…',
  done:        'CyberMind finished scanning.',
  error:       'CyberMind encountered an error.',
};

function scanLog(msg) {
  const t = document.getElementById('scan-terminal');
  if (!t) return;
  const d = document.createElement('div');
  d.textContent = `> ${msg}`;
  t.appendChild(d);
  t.scrollTop = t.scrollHeight;
}

function setProgress(pct, phase, statusMsg) {
  const bar   = document.getElementById('progress-bar');
  const label = document.getElementById('phase-label');
  const pctEl = document.getElementById('progress-pct');
  if (bar)   bar.style.width   = `${pct}%`;
  if (label) label.textContent = statusMsg || PHASE_MSGS[phase] || phase;
  if (pctEl) pctEl.textContent = `${pct}%`;
}

async function startScan() {
  const count   = parseInt(document.getElementById('packet-count')?.value || 100);
  const btn     = document.getElementById('scan-btn');
  const icon    = document.getElementById('scan-icon');
  const lbl     = document.getElementById('scan-label');
  const prog    = document.getElementById('progress-card');
  const result  = document.getElementById('scan-result');
  const err     = document.getElementById('scan-error');
  const term    = document.getElementById('scan-terminal');

  // Reset UI
  result?.classList.add('hidden');
  err?.classList.add('hidden');
  if (term) term.innerHTML = '<span class="yellow">$ cybermind-ids --scan --model model.pkl</span>';
  setProgress(0, 'starting');
  prog?.classList.remove('hidden');
  if (btn)  btn.disabled   = true;
  if (icon) icon.className = 'fa-solid fa-spinner fa-spin';
  if (lbl)  lbl.textContent = 'CyberMind is scanning…';
  if (_pollTimer) clearInterval(_pollTimer);

  try {
    // ── Step 1: POST to Flask — returns job_id instantly (no page freeze) ────
    scanLog(`CyberMind is preparing to scan ${count} packets…`);
    const startRes = await fetch('/scan/start', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ packet_count: count }),
    });
    if (!startRes.ok) throw new Error(`Server responded with ${startRes.status}`);
    const { job_id } = await startRes.json();
    scanLog(`CyberMind launched scan job ${job_id.slice(0, 8)}…`);

    // ── Step 2: Poll /scan/status every 1 second — UI stays live ─────────────
    await new Promise((resolve, reject) => {
      _pollTimer = setInterval(async () => {
        try {
          const statusRes = await fetch(`/scan/status/${encodeURIComponent(job_id)}`);
          const s = await statusRes.json();

          // Show the active-voice status_msg from the backend
          setProgress(s.progress || 0, s.phase, s.status_msg);

          if (s.phase === 'classifying') {
            scanLog('CyberMind is running the Random Forest model on the captured packets…');
          }
          if (s.status === 'done') {
            clearInterval(_pollTimer);
            scanLog(`CyberMind classified traffic as: ${s.result.label} (${Math.round(s.result.confidence * 100)}% confidence)`);
            scanLog('Result saved to cybermind_logs.db ✓');
            showResult(result, s.result);
            resolve();
          } else if (s.status === 'error') {
            clearInterval(_pollTimer);
            reject(new Error(s.error || 'Scan failed'));
          }
        } catch (e) {
          clearInterval(_pollTimer);
          reject(e);
        }
      }, 1000);
    });

  } catch (error) {
    scanLog(`CyberMind error: ${error.message}`);
    const errMsg = document.getElementById('scan-error-msg');
    if (errMsg) errMsg.textContent =
      error.message || 'CyberMind could not complete the scan. Is app.py running?';
    err?.classList.remove('hidden');
  } finally {
    if (btn)  btn.disabled   = false;
    if (icon) icon.className = 'fa-solid fa-satellite-dish';
    if (lbl)  lbl.textContent = 'START SCAN';
  }
}

// Slider → live label
document.getElementById('packet-count')?.addEventListener('input', function () {
  const lbl = document.getElementById('packet-count-label');
  if (lbl) lbl.textContent = this.value;
});


// =============================================================================
// TEXT ANALYZER
// =============================================================================

async function runAnalyze() {
  const text  = document.getElementById('analyze-text')?.value.trim();
  const srcIp = document.getElementById('analyze-ip')?.value.trim();
  const result = document.getElementById('analyze-result');
  const err   = document.getElementById('analyze-error');

  if (!text) { alert('CyberMind needs some text to analyze.'); return; }
  result?.classList.add('hidden');
  err?.classList.add('hidden');

  try {
    const res = await fetch('/analyze', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ text, source_ip: srcIp }),
    });
    if (!res.ok) throw new Error(`Server error ${res.status}`);
    const data = await res.json();

    // Normalise for shared renderer
    data.breakdown    = data.breakdown    || { [data.threat_type || 'safe']: 100 };
    data.capture_mode = 'signature';
    data.packet_count = 1;
    data.confidence   = data.confidence   ?? (data.threat_detected ? 0.9 : 0.1);
    data.severity     = data.severity     ?? (data.threat_detected ? 'critical' : 'low');
    data.verdict      = data.verdict      ||
      (data.threat_detected
        ? `🚨  CyberMind detects: ${(data.threat_type||'threat').replace(/_/g,' ')}`
        : '✅  CyberMind reports: Input looks safe');

    showResult(result, data);
  } catch (error) {
    const errMsg = document.getElementById('analyze-error-msg');
    if (errMsg) errMsg.textContent = error.message;
    err?.classList.remove('hidden');
  }
}


// =============================================================================
// LOGS SCREEN — reads from SQLite via /logs
// =============================================================================

async function loadLogs() {
  const tbody = document.getElementById('logs-body');
  const table = document.getElementById('logs-table');
  const empty = document.getElementById('logs-empty');

  try {
    const res = await fetch('/logs');
    const logs = await res.json();

    if (!logs.length) {
      empty?.classList.remove('hidden');
      table?.classList.add('hidden');
      return;
    }

    empty?.classList.add('hidden');
    table?.classList.remove('hidden');

    if (tbody) {
      tbody.innerHTML = logs.map(r => {
        const ts      = r.timestamp ? new Date(r.timestamp).toLocaleString() : '—';
        const label   = (r.label || '').replace(/_/g, ' ');
        const sevBadge = SEV_BADGE[r.severity] || 'badge-low';
        const threat   = r.threat_detected
          ? '<span class="badge badge-critical">THREAT</span>'
          : '<span class="badge badge-low">SAFE</span>';
        return `<tr>
          <td class="mono dim">${r.id}</td>
          <td class="mono" style="white-space:nowrap">${ts}</td>
          <td><span class="label-text">${label}</span></td>
          <td><span class="badge ${sevBadge}">${(r.severity||'').toUpperCase()}</span></td>
          <td class="mono">${Math.round(r.confidence * 100)}%</td>
          <td class="mono">${r.packet_count}</td>
          <td><span class="mode-tag">${r.capture_mode}</span></td>
          <td>${threat}</td>
        </tr>`;
      }).join('');
    }
  } catch (err) {
    if (empty) {
      empty.classList.remove('hidden');
      empty.querySelector('p').textContent =
        'CyberMind could not load the log database. Is app.py running?';
    }
  }
}
