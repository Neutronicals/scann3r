package reporter

import "fmt"

// buildAnalyticsDashboard produces a self-contained HTML analytics dashboard.
func buildAnalyticsDashboard(dataJSON string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>⚡ Scann3r Analysis Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg-primary: #06060f;
  --bg-card: #0d0d1a;
  --bg-card-hover: #12122a;
  --border: #1a1a3e;
  --text: #e0e0f0;
  --text-dim: #666688;
  --accent: #60efff;
  --accent2: #00ff87;
  --gradient1: linear-gradient(135deg, #60efff 0%%, #00ff87 100%%);
  --gradient2: linear-gradient(135deg, #ff0066 0%%, #ff6600 100%%);
  --critical: #ff0044;
  --high: #ff8800;
  --medium: #ffcc00;
  --low: #0088ff;
  --info: #888;
  --radius: 16px;
  --shadow: 0 4px 24px rgba(0,0,0,0.4);
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: var(--bg-primary);
  color: var(--text);
  line-height: 1.6;
  min-height: 100vh;
}
.dashboard { max-width: 1500px; margin: 0 auto; padding: 1.5rem; }

/* ─── Header ─── */
.header {
  text-align: center;
  padding: 2rem 0;
  border-bottom: 1px solid var(--border);
  margin-bottom: 2rem;
}
.header h1 {
  font-size: 2.8rem;
  font-weight: 800;
  background: var(--gradient1);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  letter-spacing: -1px;
}
.header p { color: var(--text-dim); font-size: 1rem; margin-top: .5rem; }

/* ─── Risk Gauge ─── */
.risk-section { text-align: center; margin: 2rem 0; }
.risk-gauge {
  display: inline-flex;
  align-items: center;
  gap: 1.5rem;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.5rem 3rem;
  box-shadow: var(--shadow);
}
.risk-circle {
  width: 100px; height: 100px;
  border-radius: 50%%;
  display: flex; align-items: center; justify-content: center;
  font-size: 1.8rem; font-weight: 800;
  transition: all .3s;
}
.risk-info h3 { font-size: 1.1rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; }
.risk-info .risk-label { font-size: 2rem; font-weight: 800; }

/* ─── Stats Row ─── */
.stats-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin: 2rem 0;
}
.stat-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.5rem;
  text-align: center;
  transition: all .25s;
  box-shadow: var(--shadow);
}
.stat-card:hover { transform: translateY(-4px); border-color: var(--accent); }
.stat-card .value {
  font-size: 2.5rem;
  font-weight: 800;
  background: var(--gradient1);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.stat-card .label {
  font-size: .8rem;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 1.5px;
  margin-top: .25rem;
}

/* ─── Severity Pills ─── */
.severity-row { display: flex; gap: .75rem; justify-content: center; margin: 1.5rem 0; flex-wrap: wrap; }
.sev-pill {
  padding: .6rem 1.5rem;
  border-radius: 24px;
  font-weight: 700;
  font-size: 1rem;
  display: flex; align-items: center; gap: .5rem;
}
.sev-critical { background: rgba(255,0,68,0.15); color: var(--critical); border: 1.5px solid rgba(255,0,68,0.3); }
.sev-high     { background: rgba(255,136,0,0.15); color: var(--high);     border: 1.5px solid rgba(255,136,0,0.3); }
.sev-medium   { background: rgba(255,204,0,0.15); color: var(--medium);   border: 1.5px solid rgba(255,204,0,0.3); }
.sev-low      { background: rgba(0,136,255,0.15); color: var(--low);      border: 1.5px solid rgba(0,136,255,0.3); }

/* ─── Section ─── */
.section { margin: 2.5rem 0; }
.section h2 {
  font-size: 1.4rem;
  color: var(--accent);
  margin-bottom: 1rem;
  padding-bottom: .5rem;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: .5rem;
}

/* ─── Charts Grid ─── */
.charts-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(420px, 1fr));
  gap: 1.5rem;
}
.chart-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.5rem;
  box-shadow: var(--shadow);
}
.chart-card h3 {
  font-size: 1rem;
  color: var(--text-dim);
  margin-bottom: 1rem;
  text-transform: uppercase;
  letter-spacing: .5px;
}
.chart-card canvas { max-height: 320px; }

/* ─── Tables ─── */
.table-tools { display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; align-items: center; }
.search-input {
  flex: 1; min-width: 200px;
  padding: .75rem 1rem; border-radius: 10px;
  border: 1px solid var(--border); background: var(--bg-card);
  color: var(--text); font-size: .95rem;
  transition: border-color .2s;
}
.search-input:focus { outline: none; border-color: var(--accent); }
.filter-btn {
  padding: .6rem 1.2rem; border-radius: 10px;
  border: 1px solid var(--border); background: var(--bg-card);
  color: var(--text-dim); cursor: pointer; font-size: .85rem;
  transition: all .2s;
}
.filter-btn:hover, .filter-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(96,239,255,0.08); }

table { width: 100%%; border-collapse: collapse; font-size: .85rem; }
thead th {
  text-align: left; padding: .75rem 1rem;
  background: var(--bg-card); color: var(--text-dim);
  text-transform: uppercase; font-size: .75rem; letter-spacing: .5px;
  border-bottom: 2px solid var(--border);
  position: sticky; top: 0; z-index: 1;
  cursor: pointer;
}
thead th:hover { color: var(--accent); }
tbody tr {
  border-bottom: 1px solid rgba(255,255,255,0.03);
  transition: background .15s;
}
tbody tr:hover { background: var(--bg-card-hover); }
tbody td { padding: .65rem 1rem; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sev-badge {
  display: inline-block; padding: .2rem .6rem; border-radius: 6px;
  font-weight: 600; font-size: .75rem; text-transform: uppercase;
}
.sev-badge.critical { background: rgba(255,0,68,0.2); color: var(--critical); }
.sev-badge.high     { background: rgba(255,136,0,0.2); color: var(--high); }
.sev-badge.medium   { background: rgba(255,204,0,0.2); color: var(--medium); }
.sev-badge.low      { background: rgba(0,136,255,0.2); color: var(--low); }

.type-badge {
  display: inline-block; padding: .2rem .6rem; border-radius: 6px;
  background: rgba(96,239,255,0.1); color: var(--accent);
  font-weight: 600; font-size: .75rem; text-transform: uppercase;
}

/* ─── Findings Detail ─── */
.finding-detail {
  display: none;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.5rem;
  margin: .5rem 0;
  animation: slideDown .2s ease;
}
.finding-detail.show { display: block; }
.finding-detail pre {
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
  font-family: 'Cascadia Code', 'Fira Code', monospace;
  font-size: .8rem;
  color: #aaa;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 200px;
}
@keyframes slideDown { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }

/* ─── Bar Chart Horizontal ─── */
.h-bar { display: flex; align-items: center; gap: .75rem; margin: .5rem 0; }
.h-bar .bar-label { min-width: 150px; font-size: .85rem; text-align: right; color: var(--text-dim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.h-bar .bar-track { flex: 1; height: 28px; background: rgba(255,255,255,0.03); border-radius: 6px; overflow: hidden; position: relative; }
.h-bar .bar-fill { height: 100%%; border-radius: 6px; transition: width .6s ease; display: flex; align-items: center; padding: 0 .75rem; font-size: .75rem; font-weight: 600; }
.h-bar .bar-count { min-width: 50px; font-size: .85rem; font-weight: 600; color: var(--accent); }

/* ─── Pagination ─── */
.pagination {
  display: flex; justify-content: center; gap: .5rem; margin-top: 1.5rem;
}
.page-btn {
  padding: .5rem 1rem; border-radius: 8px;
  border: 1px solid var(--border); background: var(--bg-card);
  color: var(--text-dim); cursor: pointer; font-size: .85rem;
  transition: all .2s;
}
.page-btn:hover, .page-btn.active { border-color: var(--accent); color: var(--accent); }
.page-btn:disabled { opacity: .3; cursor: default; }
.page-info { color: var(--text-dim); font-size: .85rem; padding: .5rem 1rem; display: flex; align-items: center; }

/* ─── Responsive ─── */
@media (max-width: 768px) {
  .charts-grid { grid-template-columns: 1fr; }
  .stats-row { grid-template-columns: repeat(2, 1fr); }
  .risk-gauge { flex-direction: column; padding: 1.5rem; }
}

/* ─── Footer ─── */
footer { text-align: center; padding: 2rem; color: var(--text-dim); font-size: .8rem; border-top: 1px solid var(--border); margin-top: 3rem; }
</style>
</head>
<body>
<div class="dashboard">

<!-- Header -->
<div class="header">
  <h1>⚡ SCANN3R ANALYTICS</h1>
  <p>Vulnerability Intelligence Dashboard</p>
</div>

<!-- Dynamic content rendered by JS -->
<div id="app"></div>

<footer>Generated by Scann3r v1.0.0 — Vulnerability Intelligence Dashboard</footer>
</div>

<script>
const DATA = %s;
const app = document.getElementById('app');

// ─── Utility ─── 
function esc(s) { if(!s) return ''; const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }
function sevColor(s) { return {critical:'#ff0044',high:'#ff8800',medium:'#ffcc00',low:'#0088ff',info:'#888'}[s]||'#888'; }
function truncUrl(u, n=50) { return u && u.length > n ? u.slice(0,n-3)+'...' : u; }

// ─── Build Page ─── 
let html = '';

// Risk Gauge
const riskColors = {CRITICAL:'#ff0044',HIGH:'#ff8800',MEDIUM:'#ffcc00',LOW:'#0088ff',MINIMAL:'#00ff87'};
const rc = riskColors[DATA.risk_label]||'#60efff';
html += '<div class="risk-section"><div class="risk-gauge">' +
  '<div class="risk-circle" style="border:4px solid '+rc+';color:'+rc+';box-shadow:0 0 30px '+rc+'40">'+Math.round(DATA.risk_score)+'</div>' +
  '<div class="risk-info"><h3>Overall Risk Score</h3><div class="risk-label" style="color:'+rc+'">'+DATA.risk_label+'</div></div>' +
  '</div></div>';

// Stats Row
html += '<div class="stats-row">';
[['total_findings','Findings'],['total_endpoints','Endpoints'],['total_parameters','Parameters'],['total_scans','Scans Analyzed']].forEach(([k,l]) => {
  html += '<div class="stat-card"><div class="value">'+DATA[k]+'</div><div class="label">'+l+'</div></div>';
});
html += '</div>';

// Severity Pills
html += '<div class="severity-row">';
['critical','high','medium','low'].forEach(s => {
  const c = DATA.severity_counts[s]||0;
  if(c > 0) html += '<div class="sev-pill sev-'+s+'"><span>●</span> '+s.toUpperCase()+': '+c+'</div>';
});
html += '</div>';

// Charts
html += '<div class="section"><h2>📊 Visualizations</h2><div class="charts-grid">' +
  '<div class="chart-card"><h3>Severity Distribution</h3><canvas id="sevChart"></canvas></div>' +
  '<div class="chart-card"><h3>Vulnerability Types</h3><canvas id="typeChart"></canvas></div>' +
  '<div class="chart-card"><h3>Discovery Timeline</h3><canvas id="timeChart"></canvas></div>' +
  '<div class="chart-card"><h3>Confidence Distribution</h3><canvas id="confChart"></canvas></div>' +
  '</div></div>';

// WAF Bypass Effectiveness
if(DATA.mutation_stats && DATA.mutation_stats.length > 0) {
  html += '<div class="section"><h2>🔀 WAF Bypass Effectiveness</h2>';
  const maxMut = Math.max(...DATA.mutation_stats.map(m=>m.count));
  DATA.mutation_stats.forEach(m => {
    const pct = (m.count/maxMut*100).toFixed(0);
    const color = m.strategy==='original' ? '#00ff87' : '#60efff';
    html += '<div class="h-bar"><div class="bar-label">'+esc(m.strategy)+'</div>' +
      '<div class="bar-track"><div class="bar-fill" style="width:'+pct+'%%;background:'+color+'40;color:'+color+'">'+m.percent.toFixed(1)+'%%</div></div>' +
      '<div class="bar-count">'+m.count+'</div></div>';
  });
  html += '</div>';
}

// Top Endpoints
if(DATA.top_endpoints && DATA.top_endpoints.length > 0) {
  html += '<div class="section"><h2>🎯 Most Vulnerable Endpoints</h2>';
  const maxEp = Math.max(...DATA.top_endpoints.map(e=>e.count));
  DATA.top_endpoints.forEach(e => {
    const pct = (e.count/maxEp*100).toFixed(0);
    const crit = e.critical > 0 ? ' <span style="color:#ff0044;font-size:.75rem">'+e.critical+' crit</span>' : '';
    html += '<div class="h-bar"><div class="bar-label" title="'+esc(e.url)+'">'+esc(truncUrl(e.url,45))+'</div>' +
      '<div class="bar-track"><div class="bar-fill" style="width:'+pct+'%%;background:linear-gradient(90deg,#ff004420,#ff880020)">'+crit+'</div></div>' +
      '<div class="bar-count">'+e.count+'</div></div>';
  });
  html += '</div>';
}

// Top Parameters
if(DATA.top_parameters && DATA.top_parameters.length > 0) {
  html += '<div class="section"><h2>🔑 Most Vulnerable Parameters</h2>';
  const maxPm = Math.max(...DATA.top_parameters.map(p=>p.count));
  DATA.top_parameters.forEach(p => {
    const pct = (p.count/maxPm*100).toFixed(0);
    html += '<div class="h-bar"><div class="bar-label">'+esc(p.name)+' <span style="color:#666;font-size:.7rem">('+p.location+')</span></div>' +
      '<div class="bar-track"><div class="bar-fill" style="width:'+pct+'%%;background:linear-gradient(90deg,#60efff20,#00ff8720)">'+esc(p.types)+'</div></div>' +
      '<div class="bar-count">'+p.count+'</div></div>';
  });
  html += '</div>';
}

// Findings Table
html += '<div class="section"><h2>📋 All Findings ('+DATA.findings.length+')</h2>' +
  '<div class="table-tools">' +
  '<input class="search-input" id="searchInput" placeholder="Search URLs, parameters, payloads...">' +
  '<button class="filter-btn active" data-sev="all" onclick="filterSev(this)">All</button>' +
  '<button class="filter-btn" data-sev="critical" onclick="filterSev(this)">Critical</button>' +
  '<button class="filter-btn" data-sev="high" onclick="filterSev(this)">High</button>' +
  '<button class="filter-btn" data-sev="medium" onclick="filterSev(this)">Medium</button>' +
  '<button class="filter-btn" data-sev="low" onclick="filterSev(this)">Low</button>' +
  '</div>' +
  '<div style="overflow-x:auto"><table>' +
  '<thead><tr><th onclick="sortTable(0)">Severity ↕</th><th onclick="sortTable(1)">Type ↕</th><th onclick="sortTable(2)">URL ↕</th>' +
  '<th onclick="sortTable(3)">Parameter</th><th onclick="sortTable(4)">Mutation</th><th onclick="sortTable(5)">Confidence ↕</th><th>Details</th></tr></thead>' +
  '<tbody id="findingsBody"></tbody></table></div>' +
  '<div class="pagination" id="pagination"></div></div>';

// Scans Overview
if(DATA.scans && DATA.scans.length > 0) {
  html += '<div class="section"><h2>🗂️ Scans History</h2><table>' +
    '<thead><tr><th>Scan ID</th><th>Target</th><th>Started</th><th>Status</th><th>URLs</th><th>Requests</th><th>Findings</th></tr></thead><tbody>';
  DATA.scans.forEach(s => {
    const statusColor = s.status==='completed' ? '#00ff87' : '#ffcc00';
    html += '<tr><td style="font-family:monospace;font-size:.8rem">'+esc(s.id.slice(0,8))+'...</td><td>'+esc(s.target)+'</td><td>'+esc(s.started_at)+'</td>' +
      '<td style="color:'+statusColor+'">'+esc(s.status)+'</td><td>'+s.urls_found+'</td><td>'+s.requests+'</td><td style="font-weight:700;color:var(--accent)">'+s.findings+'</td></tr>';
  });
  html += '</tbody></table></div>';
}

app.innerHTML = html;

// ─── Charts ─── 
Chart.defaults.color = '#888';
Chart.defaults.borderColor = '#1a1a3e';

// Severity Donut
new Chart(document.getElementById('sevChart'), {
  type: 'doughnut',
  data: {
    labels: Object.keys(DATA.severity_counts).map(s=>s.toUpperCase()),
    datasets: [{
      data: Object.values(DATA.severity_counts),
      backgroundColor: Object.keys(DATA.severity_counts).map(sevColor),
      borderWidth: 0, hoverOffset: 8
    }]
  },
  options: {
    cutout: '65%%',
    plugins: {
      legend: { position: 'bottom', labels: { padding: 16, usePointStyle: true, pointStyle: 'circle' } }
    }
  }
});

// Type Bar Chart
const typeLabels = Object.keys(DATA.type_counts);
const typeData = Object.values(DATA.type_counts);
const typeColors = typeLabels.map((_,i) => {
  const hue = (i * 137.5) %% 360;
  return 'hsl('+hue+', 70%%, 55%%)';
});
new Chart(document.getElementById('typeChart'), {
  type: 'bar',
  data: {
    labels: typeLabels.map(t=>t.toUpperCase()),
    datasets: [{ data: typeData, backgroundColor: typeColors, borderRadius: 6, borderSkipped: false }]
  },
  options: {
    indexAxis: 'y',
    plugins: { legend: { display: false } },
    scales: { x: { grid: { color: '#1a1a3e20' } }, y: { grid: { display: false } } }
  }
});

// Timeline
if(DATA.timeline && DATA.timeline.length > 0) {
  new Chart(document.getElementById('timeChart'), {
    type: 'line',
    data: {
      labels: DATA.timeline.map(t => t.time ? t.time.split(' ')[1] || t.time : ''),
      datasets: [{
        data: DATA.timeline.map(t=>t.count),
        borderColor: '#60efff',
        backgroundColor: 'rgba(96,239,255,0.08)',
        fill: true, tension: .35, pointRadius: 2, borderWidth: 2
      }]
    },
    options: {
      plugins: { legend: { display: false } },
      scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 10 } }, y: { grid: { color: '#1a1a3e20' }, beginAtZero: true } }
    }
  });
}

// Confidence Distribution
new Chart(document.getElementById('confChart'), {
  type: 'bar',
  data: {
    labels: DATA.confidence_distribution.map(c=>c.range),
    datasets: [{
      data: DATA.confidence_distribution.map(c=>c.count),
      backgroundColor: ['#00ff8780','#60efff80','#0088ff80','#ffcc0080','#ff880080','#ff004480'],
      borderRadius: 6, borderSkipped: false
    }]
  },
  options: {
    plugins: { legend: { display: false } },
    scales: { x: { grid: { display: false } }, y: { grid: { color: '#1a1a3e20' }, beginAtZero: true } }
  }
});

// ─── Findings Table Logic ─── 
let currentSev = 'all';
let currentSearch = '';
let currentSort = { col: 5, asc: false };
let currentPage = 0;
const PAGE_SIZE = 50;

function getFiltered() {
  return DATA.findings.filter(f => {
    if(currentSev !== 'all' && f.severity !== currentSev) return false;
    if(currentSearch) {
      const s = currentSearch.toLowerCase();
      return (f.url||'').toLowerCase().includes(s) ||
             (f.param||'').toLowerCase().includes(s) ||
             (f.payload||'').toLowerCase().includes(s) ||
             (f.type||'').toLowerCase().includes(s) ||
             (f.evidence||'').toLowerCase().includes(s);
    }
    return true;
  }).sort((a,b) => {
    const cols = ['severity','type','url','param','mutation','confidence'];
    const key = cols[currentSort.col];
    let va = a[key], vb = b[key];
    if(key === 'confidence') { va = va||0; vb = vb||0; }
    else { va = (va||'').toLowerCase(); vb = (vb||'').toLowerCase(); }
    if(key === 'severity') {
      const order = {critical:0,high:1,medium:2,low:3,info:4};
      va = order[a.severity]??5; vb = order[b.severity]??5;
    }
    if(va < vb) return currentSort.asc ? -1 : 1;
    if(va > vb) return currentSort.asc ? 1 : -1;
    return 0;
  });
}

function renderTable() {
  const filtered = getFiltered();
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  if(currentPage >= totalPages) currentPage = Math.max(0, totalPages-1);
  const start = currentPage * PAGE_SIZE;
  const page = filtered.slice(start, start + PAGE_SIZE);

  let rows = '';
  page.forEach((f, i) => {
    const idx = start + i;
    rows += '<tr onclick="toggleDetail('+idx+')" style="cursor:pointer">' +
      '<td><span class="sev-badge '+f.severity+'">'+f.severity+'</span></td>' +
      '<td><span class="type-badge">'+esc(f.type)+'</span></td>' +
      '<td title="'+esc(f.url)+'">'+esc(truncUrl(f.url,55))+'</td>' +
      '<td>'+esc(f.param)+' <span style="color:#555;font-size:.7rem">'+esc(f.param_loc)+'</span></td>' +
      '<td style="color:#666">'+esc(f.mutation||'—')+'</td>' +
      '<td><span style="color:'+confColor(f.confidence)+'">'+Math.round(f.confidence*100)+'%%</span></td>' +
      '<td style="color:var(--accent);font-size:.8rem">▶</td></tr>' +
      '<tr><td colspan="7" style="padding:0"><div class="finding-detail" id="detail-'+idx+'">' +
      '<strong style="color:var(--accent)">Payload:</strong><pre>'+esc(f.payload)+'</pre>' +
      '<strong style="color:var(--accent);margin-top:.75rem;display:block">Evidence:</strong><pre>'+esc(f.evidence)+'</pre>' +
      '<div style="margin-top:.75rem;color:#666;font-size:.8rem">Found at: '+esc(f.found_at)+' | Method: '+esc(f.method)+' | ID: '+esc(f.id)+'</div>' +
      '</div></td></tr>';
  });
  document.getElementById('findingsBody').innerHTML = rows;

  // Pagination
  let pagHtml = '<button class="page-btn" onclick="goPage(0)" '+(currentPage===0?'disabled':'')+'>«</button>' +
    '<button class="page-btn" onclick="goPage('+(currentPage-1)+')" '+(currentPage===0?'disabled':'')+'>‹</button>' +
    '<span class="page-info">'+((filtered.length>0)?(start+1)+'-'+Math.min(start+PAGE_SIZE,filtered.length)+' of '+filtered.length:'No results')+'</span>' +
    '<button class="page-btn" onclick="goPage('+(currentPage+1)+')" '+(currentPage>=totalPages-1?'disabled':'')+'>›</button>' +
    '<button class="page-btn" onclick="goPage('+(totalPages-1)+')" '+(currentPage>=totalPages-1?'disabled':'')+'>»</button>';
  document.getElementById('pagination').innerHTML = pagHtml;
}

function confColor(c) { return c >= .9 ? '#00ff87' : c >= .7 ? '#60efff' : c >= .5 ? '#ffcc00' : '#ff8800'; }

function filterSev(btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  currentSev = btn.dataset.sev;
  currentPage = 0;
  renderTable();
}

function sortTable(col) {
  if(currentSort.col === col) currentSort.asc = !currentSort.asc;
  else { currentSort.col = col; currentSort.asc = true; }
  renderTable();
}

function toggleDetail(idx) {
  const el = document.getElementById('detail-'+idx);
  if(el) el.classList.toggle('show');
}

function goPage(p) { currentPage = Math.max(0, p); renderTable(); }

document.getElementById('searchInput').addEventListener('input', function() {
  currentSearch = this.value;
  currentPage = 0;
  renderTable();
});

renderTable();
</script>
</body>
</html>`, dataJSON)
}
