let SENSORS = [], EVENTS = [], SETTINGS = {};
let activeTags = new Set(), searchQ = '', inspectId = null, graphRange = '1h';
let formTagsCache = [];
let accountModalMode = 'create';

function syncThemeIcon() {
  const icon = $('theme-icon');
  if (!icon) return;
  icon.className = document.documentElement.classList.contains('light')
    ? 'ph-bold ph-moon text-[18px]' : 'ph-bold ph-sun text-[18px]';
}

function toggleTheme() {
  const light = document.documentElement.classList.toggle('light');
  localStorage.setItem('pulsemon_theme', light ? 'light' : 'dark');
  syncThemeIcon();
}

let viewMode = localStorage.getItem('pulsemon_view') || 'cards';
const $ = id => document.getElementById(id);
syncThemeIcon();

// ---------- Authentication Flow ----------
let authState = null;
// meIsAdmin gates the admin-only UI surface (alerts, maintenance mode,
// TLS, self-update, and every SENSOR MUTATION control: new/edit/clone/
// delete/pause + clear history). Server-side, requireAdmin 403s the same
// routes for non-admin sessions (review 2026-10-28: non-admins are
// viewers + Pulse Now operators); the UI just hides the controls a
// regular account can't use. Default true: with auth off the dashboard
// is fully open, so everything stays visible.
let meIsAdmin = true;
function applyAdminVisibility() {
  const hide = !meIsAdmin;
  for (const id of ['alerts-btn', 'tls-panel', 'maint-row', 'new-sensor-btn', 'empty-add-btn', 'clear-hist-btn']) {
    const el = $(id);
    if (el) el.classList.toggle('hidden', hide);
  }
}
async function refreshAdminState() {
  if (!(authState && authState.enabled && authState.authed)) {
    meIsAdmin = true;
    applyAdminVisibility();
    return;
  }
  try {
    const users = await api('/api/auth/users');
    const me = (users || []).find(u => u.username === authState.user);
    meIsAdmin = !!(me && me.is_admin);
  } catch { meIsAdmin = true; }
  applyAdminVisibility();
  // Re-render: the per-sensor mutation buttons (edit/clone/delete/pause)
  // are built in cardHtml()/renderTable() from meIsAdmin, so the grid
  // must redraw once the admin state is known — the initial render ran
  // before this fetch resolved.
  render();
}

function showAuthGate() {
  const gate = $('auth-gate');
  if (gate) { gate.classList.remove('hidden'); $('auth-username').focus(); }
}
function hideAuthGate() {
  const gate = $('auth-gate');
  if (gate) gate.classList.add('hidden');
}
function authBlocking() { return authState && authState.enabled && !authState.authed; }

async function checkAuth() {
  try {
    const r = await fetch('/api/auth/status');
    authState = r.ok ? await r.json() : { enabled: false, authed: !r.ok };
  } catch {
    authState = { enabled: false, authed: false };
  }
  if (authBlocking()) {
    showAuthGate();
    return false;
  }
  hideAuthGate();
  return true;
}

async function doLogin(username, password) {
  try {
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username.trim(), password: password })
    });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      throw new Error(j.error || 'login failed');
    }
    authState = await r.json();
    hideAuthGate();
    $('auth-err').classList.add('hidden');
    $('auth-username').value = '';
    $('auth-password').value = '';
    // Arm the 5s pollers (idempotent; refresh()/refreshAdminState() run
    // inside it) — without this the post-login dashboard never updates.
    startPolling();
    return true;
  } catch (e) {
    const err = $('auth-err');
    err.textContent = e.message || 'invalid username or password';
    err.classList.remove('hidden');
    return false;
  }
}

$('auth-form').addEventListener('submit', e => {
  e.preventDefault();
  doLogin($('auth-username').value, $('auth-password').value);
});

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (r.status === 401) {
    await checkAuth();
    throw new Error('authentication required');
  }
  if (!r.ok) {
    let msg = r.status + ' ' + r.statusText;
    try { const j = await r.json(); if (j.error) msg = j.error; } catch {}
    throw new Error(msg);
  }
  if (r.status === 204) return null;
  return r.json();
}

async function refresh() {
  if (authBlocking()) return;
  try {
    const [s, e, hz] = await Promise.all([
      api('/api/sensors'),
      api('/api/events?n=20'),
      api('/api/healthz').catch(() => null)
    ]);
    SENSORS = s || [];
    EVENTS = e || [];
    if (hz && hz.version) { const v = $('app-ver'); if (v) v.textContent = hz.version; }
    const banner = $('probe-banner');
    if (hz && hz.icmp_hint) {
      $('probe-banner-text').textContent = 'ICMP unavailable — no pings are happening: ' + hz.icmp_hint;
      banner.classList.remove('hidden');
    } else if (hz && hz.probe_error) {
      $('probe-banner-text').textContent = 'pulsing is broken: ' + hz.probe_error;
      banner.classList.remove('hidden');
    } else {
      banner.classList.add('hidden');
    }
    render();
  } catch (err) { console.error('refresh failed', err); }
}

function fmtRtt(v) {
  if (v == null) return '—';
  return Math.round(v) + ' ms';
}

function typeLabel(s) {
  if (s.type !== 'http') return 'PING';
  return /^https:/i.test(s.target || '') ? 'HTTPS' : 'HTTP';
}

function httpStatusBadge(s) {
  if (s.type !== 'http' || s.state === 'paused' || s.http_status == null) return '';
  const code = Number.isInteger(s.http_status) ? s.http_status : null; // defensive: server type is *int
  if (code === null) return '';
  const cls = code >= 200 && code < 300 ? 'bg-ok/10 text-ok border-ok/30'
            : code >= 300 && code < 400 ? 'bg-warn/10 text-warn border-warn/30'
            : 'bg-bad/10 text-bad border-bad/30';
  return `<span class="px-1 py-0.2 rounded border text-[10px] font-mono ${cls}">${code}</span>`;
}

function certNote(s) {
  if (s.type !== 'http' || !s.cert_expiry) return '';
  const days = Math.floor((new Date(s.cert_expiry).getTime() - Date.now()) / 86400000);
  if (days < 0) return '<div class="text-[11px] font-mono text-bad flex items-center gap-1"><i class="ph-bold ph-shield-warning"></i> TLS cert expired ' + Math.abs(days) + 'd ago</div>';
  if (days <= 7) return '<div class="text-[11px] font-mono text-bad flex items-center gap-1"><i class="ph-bold ph-shield-warning"></i> TLS cert expires in ' + days + 'd</div>';
  if (days <= 30) return '<div class="text-[11px] font-mono text-warn flex items-center gap-1"><i class="ph-bold ph-shield-warning"></i> TLS cert expires in ' + days + 'd</div>';
  return '';
}

function jitterOf(s) {
  const r = (s.stats && s.stats.recent || []).filter(x => x != null);
  if (r.length < 2) return null;
  let sum = 0;
  for (let i = 1; i < r.length; i++) sum += Math.abs(r[i-1] - r[i]);
  return sum / (r.length - 1);
}

function statusMeta(s) {
  if (s.state === 'paused') {
    return { label: 'PAUSED', icon: 'ph-pause-circle', cls: 'text-slate-400 bg-slate-500/10 border-slate-500/30', dot: 'bg-slate-500', glow: '' };
  }
  switch (s.status) {
    case 'up': return { label: 'UP', icon: 'ph-check-circle', cls: 'text-ok bg-ok/10 border-ok/25', dot: 'bg-ok', glow: 'glow-ok' };
    case 'warning': return { label: 'WARN', icon: 'ph-warning', cls: 'text-warn bg-warn/10 border-warn/25', dot: 'bg-warn', glow: 'glow-warn' };
    case 'error': return { label: 'ERROR', icon: 'ph-x-circle', cls: 'text-bad bg-bad/10 border-bad/25', dot: 'bg-bad', glow: 'glow-bad' };
    default: return { label: 'UP', icon: 'ph-check-circle', cls: 'text-ok bg-ok/10 border-ok/25', dot: 'bg-ok', glow: 'glow-ok' };
  }
}

function severityRank(s) {
  const sev = s.state === 'paused' ? 3 : s.status === 'error' ? 0 : s.status === 'warning' ? 1 : 2;
  const type = s.type === 'http' ? 0 : 1;
  return sev * 2 + type;
}

// String(v ?? '') not (v || ''): the old guard dropped a legitimate 0 and
// threw on any non-string (a future numeric JSON field would blank the view
// with a bare console error; review nit 2026-10-24).
function esc(v) { return String(v ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
// escJs escapes a value for a JS string literal inside an inline HTML
// attribute (onclick="setTag('...')"). The ORDER is load-bearing:
// JS-escape FIRST (backslash, quote, CR, LF), then HTML-encode. If
// esc() ran first, ' becomes &#39; and the quote-escape below matches
// nothing — and the browser's HTML parser decodes &#39; back to a literal '
// before the JS engine ever sees it, so a stored tag like x');alert(1);//
// breaks out of the string and executes.
function escJs(v) { return esc(String(v ?? '').replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/\r/g,'\\r').replace(/\n/g,'\\n')); }

// Sparkline bar colors: red > 200 ms (absolute — objectively slow), amber at
// or above spikeMult × the window's own average (relative — a spike FOR THIS
// SENSOR, so a 6 ms bar on a 2 ms LAN link is flagged while a steady 80 ms
// WAN link stays green). spikeMult comes from the sensor row (default 5).
function sparklineBars(hour, spikeMult) {
  const arr = (hour || []).slice(0, 60);
  const vals = arr.filter(x => typeof x === 'number' && x >= 0);
  const maxVal = Math.max(...(vals.length ? vals : [0]), 100);
  const avg = vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : 0;
  const spikeAt = (spikeMult > 0 && avg > 0) ? spikeMult * avg : 0;
  return arr.map(v => {
    if (v === null) return '<div class="spark-bar flex-1 h-full bg-bad/80 rounded-sm" title="packet lost"></div>';
    if (v === -2) return '<div class="spark-bar flex-1 h-[8%] bg-surface-700/40 rounded-sm" title="no data"></div>';
    const h = Math.min(100, Math.max(12, (v / maxVal) * 100));
    let cls = 'bg-ok/80';
    if (v > 200) cls = 'bg-bad'; else if (spikeAt > 0 && v >= spikeAt) cls = 'bg-warn';
    return '<div class="spark-bar flex-1 rounded-sm ' + cls + '" style="height:' + h + '%" title="' + fmtRtt(v) + '"></div>';
  }).join('');
}

function render() {
  const up = SENSORS.filter(s => s.state === 'active' && s.status === 'up').length;
  const warn = SENSORS.filter(s => s.state === 'active' && s.status === 'warning').length;
  const err = SENSORS.filter(s => s.state === 'active' && s.status === 'error').length;
  const paused = SENSORS.filter(s => s.state === 'paused').length;

  $('c-up').textContent = up; $('c-warn').textContent = warn; $('c-error').textContent = err; $('c-paused').textContent = paused;
  $('m-up').textContent = up; $('m-warn').textContent = warn; $('m-error').textContent = err; $('m-paused').textContent = paused;

  const tags = ['ALL'].concat([...new Set(SENSORS.flatMap(s => s.tags || []))]);
  const on = 'bg-surface-700 text-white font-semibold border border-surface-600';
  const off = 'text-slate-400 hover:text-white bg-surface-950/60 border border-surface-800';
  $('tag-chips').innerHTML = tags.map(t => {
    if (t === 'ALL') {
      return '<button onclick="setTag(\'ALL\')" class="px-2.5 py-1 rounded-md whitespace-nowrap transition ' +
        (activeTags.size === 0 ? on : off) + '">ALL</button>';
    }
    return '<button onclick="setTag(\'' + escJs(t) + '\')" class="px-2.5 py-1 rounded-md whitespace-nowrap transition ' +
      (activeTags.has(t) ? on : off) + '">' + esc(t) + '</button>';
  }).join('');

  let list = SENSORS.filter(s => (activeTags.size === 0 || [...activeTags].some(t => (s.tags || []).includes(t))) &&
    (!searchQ || s.name.toLowerCase().includes(searchQ) || s.target.toLowerCase().includes(searchQ) || (s.tags || []).join(' ').toLowerCase().includes(searchQ)));

  const sort = $('sort').value;
  list.sort((a, b) => {
    if (sort === 'severity') return severityRank(a) - severityRank(b) || a.name.localeCompare(b.name);
    if (sort === 'name') return a.name.localeCompare(b.name);
    const ra = a.stats ? (a.stats.rtt_last != null ? a.stats.rtt_last : 99999) : 99999;
    const rb = b.stats ? (b.stats.rtt_last != null ? b.stats.rtt_last : 99999) : 99999;
    if (sort === 'rtt-desc') return rb - ra;
    if (sort === 'rtt-asc') return ra - rb;
    if (sort === 'loss') return (b.stats && b.stats.hour_loss_pct || 0) - (a.stats && a.stats.hour_loss_pct || 0);
    return 0;
  });

  const grid = $('grid'), empty = $('empty'), tableWrap = $('table-wrap');
  if (SENSORS.length === 0) {
    grid.innerHTML = ''; tableWrap.classList.add('hidden'); empty.classList.remove('hidden');
    $('empty-title').textContent = 'No sensors yet';
    $('empty-sub').textContent = 'Add your first sensor to start monitoring.';
  } else if (list.length === 0) {
    grid.innerHTML = ''; tableWrap.classList.add('hidden'); empty.classList.remove('hidden');
    $('empty-title').textContent = 'No sensors match your filter';
    $('empty-sub').textContent = 'Clear search query or active tag selections.';
  } else {
    empty.classList.add('hidden');
    if (viewMode === 'table') {
      grid.innerHTML = '';
      tableWrap.classList.remove('hidden');
      renderTable(list);
    } else {
      tableWrap.classList.add('hidden');
      grid.innerHTML = list.map(cardHtml).join('');
    }
  }

  $('feed').innerHTML = EVENTS.length ? EVENTS.map(ev => {
    const icon = ev.to === 'error' ? 'ph-arrow-down text-bad' : ev.to === 'warning' ? 'ph-arrow-up text-warn' : 'ph-arrow-up text-ok';
    const d = new Date(ev.ts);
    const t = (d.toDateString() === new Date().toDateString())
      ? d.toLocaleTimeString([], { hour12: false })
      : d.toLocaleDateString('en-US', { month: '2-digit', day: '2-digit' }) + ' ' + d.toLocaleTimeString([], { hour12: false });
    return '<li class="px-4 py-2 flex items-center gap-2">' +
      '<i class="ph ' + icon + ' text-[13px]"></i>' +
      '<span class="text-slate-300 font-semibold">' + esc(ev.sensor) + '</span>' +
      '<span class="text-slate-500">' + esc(ev.from) + ' → <span class="text-slate-300">' + esc(ev.to) + '</span></span>' +
      '<span class="ml-auto text-slate-500 text-[11px]">' + t + '</span></li>';
  }).join('') : '<li class="px-4 py-3 text-slate-500">no recent state transitions</li>';
  layoutSparklines();
  rearmDeleteConfirm();
}

function layoutSparklines() {
  // Round each bar to a whole number of PHYSICAL (device) pixels so the browser
  // rasterizes every bar identically. A fractional CSS width (e.g. 4.14px) is
  // invisible on a 1x screen but, on fractionally-scaled high-DPI displays
  // (1.25x / 1.5x), beats against the pixel grid and produces a periodic
  // "wide bar every Nth" pattern. Snapping to device pixels kills it.
  const dpr = window.devicePixelRatio || 1;
  document.querySelectorAll('.h-9.flex').forEach(c => {
    const bars = c.querySelectorAll('.spark-bar');
    if (bars.length !== 60) return;
    const cs = getComputedStyle(c);
    const inner = c.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
    const gap = 2;
    const innerD = inner * dpr;
    const gapD = gap * dpr;
    // FLOOR, not round: with 60 bars, Math.round can inflate the total bar
    // width by up to ~30px past the container (0.5px x 60), spilling the bars
    // out of the box at certain window widths. Floor guarantees the snapped
    // total <= inner while keeping the device-pixel snap from v0.2.7.
    const barD = Math.max(1, Math.floor((innerD - (bars.length - 1) * gapD) / bars.length));
    const w = barD / dpr;
    bars.forEach(b => { b.style.flex = 'none'; b.style.width = w + 'px'; });
  });
}

function cardHtml(s) {
  const m = statusMeta(s);
  const st = s.stats;
  const paused = s.state === 'paused';
  const isHttp = s.type === 'http';
  const rttIsErr = !paused && s.status === 'error' && !(st && st.rtt_last != null);
  const rtt = paused ? '—' : (st && st.rtt_last != null ? fmtRtt(st.rtt_last) : (rttIsErr ? 'error' : 'no data'));
  const loss = paused ? '—' : (st ? st.hour_loss_pct.toFixed(1) + '%' : '—');
  const j = jitterOf(s);
  const jit = paused ? '—' : (j != null ? '±' + fmtRtt(j) : '—');
  const cert = certNote(s);
  const border = paused ? 'border-surface-700/80' : s.status === 'error' ? 'border-bad/40' : s.status === 'warning' ? 'border-warn/40' : 'border-surface-800';
  const badge = httpStatusBadge(s);

  return '<div class="bg-surface-900 border ' + border + ' rounded-xl p-2.5 pb-1 flex flex-col gap-2 transition hover:shadow-lg hover:shadow-black/20 ' + (paused ? 'opacity-70' : '') + '">' +
    '<div class="flex items-start justify-between gap-2">' +
      '<div class="flex items-start gap-2 min-w-0 cursor-pointer" onclick="openInspector(\'' + escJs(s.id) + '\')">' +
        '<i class="ph-bold ' + m.icon + ' text-[16px] shrink-0 mt-px ' + (m.label === 'PAUSED' ? 'text-slate-500' : m.label === 'UP' ? 'text-ok' : m.label === 'WARN' ? 'text-warn' : 'text-bad') + '"></i>' +
        '<div class="min-w-0">' +
          '<div class="flex items-center gap-1.5 min-w-0">' +
            '<h3 class="text-[14px] font-semibold text-slate-100 font-mono truncate hover:text-ok">' + esc(s.name) + '</h3>' +
            '<span class="px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold border ' + (isHttp ? 'bg-jit/10 border-jit/30 text-jit' : 'bg-surface-800 border-surface-700 text-slate-400') + '">' + typeLabel(s) + '</span>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<span class="px-2 py-0.5 rounded text-[11px] font-mono font-semibold border flex items-center gap-1 shrink-0 ' + m.cls + '"><i class="ph ' + m.icon + '"></i> ' + m.label + '</span>' +
    '</div>' +

    '<div class="flex flex-wrap items-start gap-1 min-h-[2.5rem]">' +
      ((s.tags || []).length ? (s.tags || []).map(t => '<span class="text-[11px] font-mono text-slate-500 px-1.5 py-0.2 rounded bg-surface-950 border border-surface-800">' + esc(t) + '</span>').join('') : '') +
    '</div>' +

    '<div class="grid grid-cols-3 gap-2 p-2 bg-surface-950/70 rounded-lg border border-surface-800/80 font-mono text-center">' +
      '<div>' +
        '<div class="text-[10px] text-slate-500 uppercase flex items-center justify-center gap-1">' + typeLabel(s) + ' ' + badge + '</div>' +
        '<div class="text-[14px] font-bold mt-0.5 ' + (rttIsErr ? 'text-bad' : 'text-slate-100') + '">' + rtt + '</div>' +
      '</div>' +
      '<div class="border-x border-surface-800/80">' +
        '<div class="text-[10px] text-slate-500 uppercase">Jitter</div>' +
        '<div class="text-[14px] font-bold text-jit mt-0.5">' + jit + '</div>' +
      '</div>' +
      '<div>' +
        '<div class="text-[10px] text-slate-500 uppercase">Loss</div>' +
        '<div class="text-[14px] font-bold mt-0.5 ' + (!paused && st && st.hour_loss_pct > 0 ? 'text-warn' : 'text-slate-300') + '">' + loss + '</div>' +
      '</div>' +
    '</div>' +

    (cert ? cert : '') +

    '<div>' +
      '<div class="flex items-center justify-between text-[11px] text-slate-500 font-mono mb-1">' +
        '<span>past 1h</span>' +
        (!paused && st && st.total ? '<span>uptime 24h: ' + st.uptime_24h.toFixed(2) + '%' + '</span>' : '') +
      '</div>' +
      '<div class="h-9 flex ' + (paused || !(st && st.hour) ? 'items-center justify-center' : 'items-end justify-center') + ' gap-[2px] p-1 overflow-hidden bg-surface-950/70 border border-surface-800/80 rounded">' +
        (paused ? '<span class="text-[11px] text-slate-600 font-mono">paused</span>'
          : (st && st.hour ? sparklineBars(st.hour, s.spike_mult) : '<span class="text-[11px] text-slate-600 font-mono">collecting…</span>')) +
      '</div>' +
    '</div>' +

    '<div class="flex items-end justify-between mt-auto pt-1.5 border-t border-surface-800/60">' +
      '<button onclick="echoPing(\'' + escJs(s.id) + '\', this)" title="Pulse Now" class="p-1 rounded text-slate-500 hover:text-ok transition"><i class="ph-bold ph-paper-plane-tilt text-[14px]"></i></button>' +
      // Mutation cluster (pause/edit/clone/delete) is admin-only — the
      // server 403s these for non-admin sessions (requireAdmin); the UI
      // just hides what a regular account can't use. Pulse Now stays.
      (meIsAdmin ? '<div class="flex items-center gap-0.5">' +
        '<button onclick="togglePause(\'' + escJs(s.id) + '\')" title="' + (paused ? 'Resume' : 'Pause') + '" class="p-1 rounded ' + (paused ? 'text-warn' : 'text-slate-500 hover:text-warn') + ' transition"><i class="ph-bold ' + (paused ? 'ph-play' : 'ph-pause') + ' text-[14px]"></i></button>' +
        '<button onclick="openSensorModal(\'' + escJs(s.id) + '\')" title="Edit" class="p-1 rounded text-slate-500 hover:text-sky-400 transition"><i class="ph-bold ph-pencil-simple text-[14px]"></i></button>' +
        '<button onclick="cloneSensor(\'' + escJs(s.id) + '\')" title="Clone" class="p-1 rounded text-slate-500 hover:text-jit transition"><i class="ph-bold ph-copy text-[14px]"></i></button>' +
        '<button onclick="confirmInlineDelete(\'' + escJs(s.id) + '\', \'' + escJs(s.name) + '\', this)" title="Delete" class="p-1 rounded text-slate-500 hover:text-bad transition" data-del="' + esc(s.id) + '"><i class="ph-bold ph-trash text-[14px]"></i></button>' +
      '</div>' : '') +
    '</div>' +
  '</div>';
}

function miniSpark(recent) {
  const arr = (recent || []).slice(0, 20).reverse();
  const vals = arr.filter(x => x != null);
  const maxVal = Math.max(...(vals.length ? vals : [0]), 20);
  return arr.map(v => {
    // Per-bar title= like sparklineBars (review nit): the table Trend
    // column had no per-point readout while the cards did.
    if (v == null) return '<div class="w-[2.5px] h-4 bg-bad/80 rounded-sm" title="packet lost"></div>';
    const h = Math.min(18, Math.max(3, (v / maxVal) * 18));
    let cls = 'bg-ok/70';
    if (v > 200) cls = 'bg-bad'; else if (v >= 100) cls = 'bg-warn';
    return '<div class="w-[2.5px] rounded-sm ' + cls + '" style="height:' + h + 'px" title="' + fmtRtt(v) + '"></div>';
  }).join('');
}

function renderTable(list) {
  $('table-body').innerHTML = list.map(s => {
    const m = statusMeta(s);
    const st = s.stats;
    const paused = s.state === 'paused';
    const rtt = paused ? '—' : (st && st.rtt_last != null ? fmtRtt(st.rtt_last) : '—');
    const j = jitterOf(s);
    const jit = paused ? '—' : (j != null ? '±' + fmtRtt(j) : '—');
    const loss = paused ? '—' : (st ? st.hour_loss_pct.toFixed(1) + '%' : '—');
    const up24 = paused ? '—' : (st && st.total ? st.uptime_24h.toFixed(2) + '%' : '—');
    const cert = s.type === 'http' ? (certNote(s) ? ' <span class="text-warn text-[10px]">⚠ cert</span>' : '') : '';
    const badge = httpStatusBadge(s);

    return '<tr class="hover:bg-surface-850/50 transition-colors">' +
      '<td class="py-2 px-3.5"><span class="inline-flex items-center gap-1.5 ' + m.cls.split(' ')[0] + ' font-semibold"><span class="w-2 h-2 rounded-full ' + m.dot + '"></span>' + m.label + '</span></td>' +
      '<td class="py-2 px-3.5 font-semibold text-slate-200"><span class="hover:text-ok cursor-pointer" onclick="openInspector(\'' + escJs(s.id) + '\')">' + esc(s.name) + '</span><span class="ml-1.5 px-1 py-0.2 rounded text-[10px] font-mono border ' + (s.type === 'http' ? 'bg-jit/10 border-jit/30 text-jit' : 'bg-surface-800 border-surface-700 text-slate-500') + '">' + typeLabel(s) + '</span></td>' +
      '<td class="url-mono py-2 px-3.5 text-slate-500 text-[12px] hidden md:table-cell max-w-[200px] truncate">' + esc(s.target) + '</td>' +
      '<td class="py-2 px-3.5">' + ((s.tags || []).length ? (s.tags || []).map(t => '<span class="inline-block px-1.5 py-0.2 rounded text-[11px] bg-surface-950 border border-surface-800 text-slate-400 mr-1">' + esc(t) + '</span>').join('') : '<span class="text-slate-600">—</span>') + '</td>' +
      '<td class="py-2 px-3.5 text-right font-semibold ' + (st && st.rtt_last != null ? 'text-slate-100' : 'text-slate-500') + '"><span class="mr-1">' + badge + '</span>' + rtt + cert + '</td>' +
      '<td class="py-2 px-3.5 text-right text-jit">' + jit + '</td>' +
      '<td class="py-2 px-3.5 text-right ' + (!paused && st && st.hour_loss_pct > 0 ? 'text-warn font-semibold' : 'text-slate-400') + '">' + loss + '</td>' +
      '<td class="py-2 px-3.5 text-right ' + (st && st.total ? (st.uptime_24h < 99 ? 'text-warn font-semibold' : 'text-ok') : 'text-slate-500') + '">' + up24 + '</td>' +
      '<td class="py-2 px-3.5 hidden lg:table-cell"><div class="flex items-end gap-[1.5px] h-5">' + (paused ? '<span class="text-[11px] text-slate-600">paused</span>' : miniSpark(st && st.recent)) + '</div></td>' +
      '<td class="py-2 px-3.5 text-right"><div class="flex items-center justify-end gap-1">' +
        '<button onclick="echoPing(\'' + escJs(s.id) + '\', this)" title="Pulse Now" class="p-1 rounded text-slate-500 hover:text-ok"><i class="ph-bold ph-paper-plane-tilt"></i></button>' +
        // Admin-only mutation cluster (mirrors cardHtml); non-admins keep Pulse Now.
        (meIsAdmin ?
        '<button onclick="togglePause(\'' + escJs(s.id) + '\')" title="' + (paused ? 'Resume' : 'Pause') + '" class="p-1 rounded ' + (paused ? 'text-warn' : 'text-slate-500 hover:text-warn') + '"><i class="ph-bold ' + (paused ? 'ph-play' : 'ph-pause') + '"></i></button>' +
        '<button onclick="openSensorModal(\'' + escJs(s.id) + '\')" title="Edit" class="p-1 rounded text-slate-500 hover:text-sky-400"><i class="ph-bold ph-pencil-simple"></i></button>' +
        '<button onclick="cloneSensor(\'' + escJs(s.id) + '\')" title="Clone" class="p-1 rounded text-slate-500 hover:text-jit"><i class="ph-bold ph-copy"></i></button>' +
        '<button onclick="confirmInlineDelete(\'' + escJs(s.id) + '\', \'' + escJs(s.name) + '\', this)" title="Delete" class="p-1 rounded text-slate-500 hover:text-bad" data-del="' + esc(s.id) + '"><i class="ph-bold ph-trash"></i></button>' : '') +
      '</div></td></tr>';
  }).join('');
}

document.addEventListener('input', e => {
  // Search box only (review 2026-10-24): the old version re-rendered the
  // WHOLE dashboard on any keystroke in ANY field — including the
  // settings-modal inputs, whose typed characters were re-rendered
  // underneath the user by the 5s poll loop.
  if (e.target.id !== 'q') return;
  searchQ = e.target.value.trim().toLowerCase();
  render();
});

function setTag(t) {
  if (t === 'ALL') activeTags.clear();
  else if (activeTags.has(t)) activeTags.delete(t);
  else activeTags.add(t);
  render();
}

function setViewMode(m) {
  viewMode = m;
  localStorage.setItem('pulsemon_view', m);
  $('view-cards-btn').className = 'p-1.5 rounded transition ' + (m === 'cards' ? 'text-white bg-surface-800' : 'text-slate-400 hover:text-white');
  $('view-table-btn').className = 'p-1.5 rounded transition ' + (m === 'table' ? 'text-white bg-surface-800' : 'text-slate-400 hover:text-white');
  render();
}

// ---------- Inline Confirmation Handlers (replaces blocking confirm()) ----------
// The delete-confirm is armed by SENSOR ID, not by a captured button
// reference (review 2026-10-24): the 5s poll re-renders the grid/table from
// innerHTML, which used to wipe an armed "CONFIRM?" button mid-delete — the
// two-click confirm silently reset under the user's cursor. pendingDeleteId
// survives the re-render and re-arms the freshly-built button.
let pendingDeleteId = null;
let pendingDeleteTimer = null;
function armDeleteConfirm(btn) {
  if (btn.dataset.confirming === "true") return;
  btn.dataset.confirming = "true";
  btn.innerHTML = '<span class="text-bad text-[10px] font-bold font-mono px-1">CONFIRM?</span>';
  btn.classList.add('bg-bad/10', 'border', 'border-bad/30');
}
function clearPendingDelete() {
  pendingDeleteId = null;
  if (pendingDeleteTimer) { clearTimeout(pendingDeleteTimer); pendingDeleteTimer = null; }
}
function confirmInlineDelete(id, name, btn) {
  if (pendingDeleteId === id) {   // second click → delete
    clearPendingDelete();
    deleteSensor(id, name);
    return;
  }
  pendingDeleteId = id;
  armDeleteConfirm(btn);
  if (pendingDeleteTimer) clearTimeout(pendingDeleteTimer);
  pendingDeleteTimer = setTimeout(clearPendingDelete, 4000);
}
// Re-arm after every render() so the armed state is visible across the poll.
function rearmDeleteConfirm() {
  if (!pendingDeleteId) return;
  const btn = document.querySelector('[data-del="' + pendingDeleteId + '"]');
  if (btn) armDeleteConfirm(btn); else clearPendingDelete();
}
// Click anywhere outside the armed button disarms (re-render-safe: keyed on
// the id, and bubbling order is onclick handler first, then this listener).
document.addEventListener('click', e => {
  if (!pendingDeleteId) return;
  const t = e.target.closest && e.target.closest('[data-del]');
  if (t && t.dataset.del === pendingDeleteId) return;
  clearPendingDelete();
  render();
});

function confirmClearActivity(btn) {
  if (!EVENTS.length) { toast('activity log is already empty', 'ok'); return; }
  if (btn.dataset.confirming === "true") {
    clearActivity();
    btn.textContent = "Clear";
    btn.dataset.confirming = "false";
    return;
  }
  btn.dataset.confirming = "true";
  btn.textContent = "Confirm Wipe?";
  btn.classList.add("text-bad");
  setTimeout(() => {
    btn.dataset.confirming = "false";
    btn.textContent = "Clear";
    btn.classList.remove("text-bad");
  }, 3000);
}

function confirmClearHistory(btn) {
  if (btn.dataset.confirming === "true") {
    clearHistory();
    btn.innerHTML = '<i class="ph ph-trash"></i> Clear History';
    btn.dataset.confirming = "false";
    return;
  }
  btn.dataset.confirming = "true";
  btn.innerHTML = '<span class="text-bad font-semibold">Confirm Purge?</span>';
  setTimeout(() => {
    btn.dataset.confirming = "false";
    btn.innerHTML = '<i class="ph ph-trash"></i> Clear History';
  }, 3000);
}

function confirmRemoveTLSCert(btn) {
  if (btn.dataset.confirming === "true") {
    removeTLSCert();
    btn.textContent = "Remove Cert";
    btn.dataset.confirming = "false";
    return;
  }
  btn.dataset.confirming = "true";
  btn.textContent = "Confirm Removal?";
  btn.classList.add("text-bad");
  setTimeout(() => {
    btn.dataset.confirming = "false";
    btn.textContent = "Remove Cert";
    btn.classList.remove("text-bad");
  }, 3000);
}

function confirmDisableAuth(btn) {
  if (btn.dataset.confirming === "true") {
    disableAuth();
    btn.textContent = "Disable Auth";
    btn.dataset.confirming = "false";
    return;
  }
  btn.dataset.confirming = "true";
  btn.textContent = "Confirm Disable?";
  setTimeout(() => {
    btn.dataset.confirming = "false";
    btn.textContent = "Disable Auth";
  }, 3000);
}

let echoBusy = false;
async function echoPing(id, btn) {
  if (echoBusy) return;
  echoBusy = true;
  if (btn) btn.disabled = true;
  try {
    const r = await api('/api/sensors/' + id + '/ping', { method: 'POST' });
    if (btn) {
      btn.classList.add(r.lost ? 'text-bad' : 'text-ok');
      setTimeout(() => { btn.classList.remove('text-bad', 'text-ok'); btn.disabled = false; }, 1500);
    }
    let msg = r.lost ? 'no reply from host'
      : (r.http_status != null ? 'pulse: HTTP ' + r.http_status + ' · ' + fmtRtt(r.rtt_ms) : 'pulse: ' + fmtRtt(r.rtt_ms));
    toast(msg, r.lost ? 'bad' : 'ok');
  } catch (e) {
    toast('pulse failed: ' + e.message, 'bad');
    // Re-enable on failure too — with the old code a single failed pulse
    // left the button permanently dead in views that only re-render on
    // data change (review 2026-10-24).
    if (btn) btn.disabled = false;
  }
  echoBusy = false;
}

async function togglePause(id) {
  const s = SENSORS.find(x => x.id === id); if (!s) return;
  const next = s.state === 'paused' ? 'active' : 'paused';
  try {
    await api('/api/sensors/' + id, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ state: next }) });
    toast(s.name + (next === 'paused' ? ' paused' : ' resumed'), 'ok');
    await refresh();
  } catch (e) { toast(e.message, 'bad'); }
}

async function cloneSensor(id) {
  try {
    const c = await api('/api/sensors/' + id + '/clone', { method: 'POST' });
    toast('cloned → ' + c.name, 'ok');
    await refresh();
  } catch (e) { toast(e.message, 'bad'); }
}

async function deleteSensor(id, name) {
  try {
    await api('/api/sensors/' + id, { method: 'DELETE' });
    toast(name + ' deleted', 'ok');
    if (inspectId === id) closeInspector();
    await refresh();
  } catch (e) { toast(e.message, 'bad'); }
}

async function clearActivity() {
  try {
    const r = await api('/api/events', { method: 'DELETE' });
    EVENTS = [];
    render();
    toast('activity log cleared' + (r && r.events_deleted != null ? ' (' + r.events_deleted + ' entries)' : ''), 'ok');
  } catch (e) { toast(e.message, 'bad'); }
}

// ---------- Sensor Form Tag Picker ----------
function allExistingTags() { return [...new Set(SENSORS.flatMap(s => s.tags || []))].sort(); }

function renderFormTags(selected) {
  const box = $('f-tagchips');
  if (!selected.length) {
    box.innerHTML = '<span class="text-[11px] text-slate-500 font-mono">no tags assigned</span>';
  } else {
    box.innerHTML = selected.map(t =>
      '<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-surface-800 border border-surface-700 text-[11px] font-mono text-slate-200">' +
      esc(t) + '<button type="button" onclick="removeFormTag(\'' + escJs(t) + '\')" class="text-slate-500 hover:text-bad"><i class="ph ph-x"></i></button></span>').join('');
  }
  const pick = $('f-tagpick');
  const cur = pick.value;
  pick.innerHTML = '<option value="">+ add existing tag…</option>' +
    allExistingTags().filter(t => !selected.includes(t)).map(t => '<option value="' + esc(t) + '">' + esc(t) + '</option>').join('');
  if ([...pick.options].some(o => o.value === cur)) pick.value = cur;
}

function addFormTag(t) {
  if (!t || formTagsCache.includes(t)) return;
  formTagsCache.push(t);
  renderFormTags(formTagsCache);
}

function removeFormTag(t) {
  formTagsCache = formTagsCache.filter(x => x !== t);
  renderFormTags(formTagsCache);
}

function selectedFormTags() { return formTagsCache.slice(); }

function openSensorModal(id) {
  $('form-err').classList.add('hidden');
  formTagsCache = [];
  if (id) {
    const s = SENSORS.find(x => x.id === id); if (!s) return;
    $('modal-title').textContent = 'Edit Sensor';
    $('f-id').value = s.id; $('f-name').value = s.name; $('f-target').value = s.target;
    $('f-type').value = s.type === 'http' ? 'http' : 'icmp';
    onFormTypeChange();
    formTagsCache = (s.tags || []).slice();
    renderFormTags(formTagsCache);
    $('f-interval').value = s.interval_s; $('f-timeout').value = s.timeout_ms; $('f-loss').value = s.loss_warn; $('f-down').value = s.down_after; $('f-spike').value = s.spike_mult || 5;
  } else {
    $('modal-title').textContent = 'New Sensor';
    $('f-id').value = ''; $('f-name').value = ''; $('f-target').value = '';
    $('f-type').value = 'http';
    onFormTypeChange();
    renderFormTags([]);
    $('f-interval').value = 60; $('f-timeout').value = 1000; $('f-loss').value = 25; $('f-down').value = 2; $('f-spike').value = 5;
  }
  $('modal-backdrop').classList.remove('hidden');
  setTimeout(() => $('f-name').focus(), 50);
}

function onFormTypeChange() {
  const isHttp = $('f-type').value === 'http';
  $('f-target-hint').textContent = isHttp ? 'URL (http:// or https://)' : 'IP or hostname';
  $('f-target').placeholder = isHttp ? 'https://example.com/health' : '10.0.0.1';
  $('f-type-hint').textContent = isHttp
    ? 'GETs URL — marks up on 2xx status code'
    : 'pulses with ICMP echo — up when host replies';
}

function closeModal() { $('modal-backdrop').classList.add('hidden'); }

function nameErr(name) {
  if (!name) return 'name is required';
  if (name.length > 60) return 'name must be 60 characters or fewer';
  let bad = /['"`\\<>]/.test(name);
  if (!bad) {
    for (let i = 0; i < name.length; i++) {
      let c = name.codePointAt(i);
      if (c < 0x20 || c === 0x7f) { bad = true; break; }
    }
  }
  if (bad) return 'name may not contain quotes, backslash, < >, or control characters';
  return '';
}

async function submitSensor(ev) {
  ev.preventDefault();
  const id = $('f-id').value;
  const body = {
    name: $('f-name').value.trim(), target: $('f-target').value.trim(), type:$('f-type').value, tags: selectedFormTags(),
    interval_s: +$('f-interval').value, timeout_ms: +$('f-timeout').value,
    loss_warn: +$('f-loss').value, down_after: +$('f-down').value, spike_mult: +$('f-spike').value
  };
  const ne = nameErr(body.name);
  if (ne) { $('form-err').textContent = ne; $('form-err').classList.remove('hidden'); return; }
  try {
    if (id) {
      await api('/api/sensors/' + id, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      toast('sensor updated', 'ok');
    } else {
      await api('/api/sensors', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      toast('sensor created', 'ok');
    }
    closeModal();
    await refresh();
  } catch (e) {
    $('form-err').textContent = e.message; $('form-err').classList.remove('hidden');
  }
}

// ---------- Settings & Alert Routing ----------
const PROVIDER_META = {
  google_chat: { icon: '💬', name: 'Google Chat' },
  discord:     { icon: '🎮', name: 'Discord' },
  telegram:    { icon: '✈️', name: 'Telegram' },
  smtp:        { icon: '📧', name: 'Email (SMTP)' }
};
function providerMeta(kind) { return PROVIDER_META[kind] || { icon: '📡', name: kind.replace(/_/g, ' ') }; }
// Safe value readers for the provider extra-field inputs (undefined → '').
function val(id) { const el = $(id); return el ? el.value.trim() : ''; }
function sel(id) { const el = $(id); return el ? el.value : ''; }

async function openSettings() {
  $('set-msg').classList.add('hidden');
  $('settings-backdrop').classList.remove('hidden');
  try {
    const s = await api('/api/settings');
    SETTINGS = s;
    setMaintUI(SETTINGS.maintenance_mode === true);
    renderTLSStatus(s.tls);
    renderAuthPanel();
    $('f-tls-cert-file').value = '';$('f-tls-key-file').value = '';
    $('tls-cert-file-name').textContent = 'Certificate (CRT/PEM)';$('tls-key-file-name').textContent = 'Private Key (KEY/PEM)';
  } catch (e) {
    setMsg('Failed to load settings: ' + (e.message || 'request failed'), 'bad');
  }
  checkUpdate(false);  // keep the Version row current when Settings opens
}
function closeSettings() { $('settings-backdrop').classList.add('hidden'); }

async function openAlerts() {
  $('alert-msg').classList.add('hidden');
  $('set-summary').textContent = 'loading…';
  $('alerts-backdrop').classList.remove('hidden');
  try {
    const s = await api('/api/settings');
    SETTINGS = s;
    renderProviderList(s.providers || []);
    $('f-scope').value = s.alert_scope || 'all';
    $('f-realert').value = s.realert_min ?? 30;
    renderScopeOptions();
  } catch (e) {
    $('set-summary').textContent = 'load failed';
    $('set-summary').className = 'px-2 py-0.5 rounded bg-bad/10 border border-bad/40 text-bad';
    // Informative empty-state so the section doesn't read as "the feature is gone"
    const box = $('provider-list');
    if (box) box.innerHTML = '<div class="border border-bad/40 rounded-lg px-3 py-2 bg-bad/5 text-[12px] font-mono text-bad flex items-center gap-2"><i class="ph-bold ph-warning"></i> Could not load alert settings (<span>' + esc(e.message || 'request failed') + '</span>). <button onclick="openAlerts()" class="ml-auto underline hover:text-white">Retry</button></div>';
    setMsg('Failed to load alert settings: ' + (e.message || 'request failed'), 'bad', 'alerts');
  }
}
function closeAlerts() { $('alerts-backdrop').classList.add('hidden'); }

// ---------- Update check ----------
async function checkUpdate(force) {
  try {
    const r = await api('/api/update-check' + (force ? '?refresh=1' : ''));
    renderUpdateUI(r);
  } catch (e) {
    // Non-fatal: the dashboard works fine without the update check.
    const body = $('ver-body');
    if (body) body.innerHTML = '<span class="text-slate-500">update check unavailable</span><span class="text-slate-600">' + esc(e.message || '') + '</span>';
  }
}
function renderUpdateUI(r) {
  UPDATE_LATEST = r.latest || UPDATE_LATEST;
  // Header pill: show only when an update is available and not dismissed.
  const pill = $('update-pill');
  const dismissed = localStorage.getItem('pulsemon_update_dismissed') === r.latest;
  if (r.available && !dismissed) {
    $('update-pill-ver').textContent = r.latest;
    pill.classList.remove('hidden');
  } else if (pill) pill.classList.add('hidden');
  // Settings version row.
  const body = $('ver-body');
  if (!body) return;
  if (r.available) {
    body.innerHTML =
      '<span>running <b class="text-slate-200">' + esc(r.running) + '</b> · latest <b class="text-warn">' + esc(r.latest) + '</b></span>' +
      '<span class="flex items-center gap-2">' +
      (meIsAdmin ? '<button id="update-btn" onclick="startUpdate()" title="Download and install ' + esc(r.latest) + ' now" class="px-2 py-0.5 rounded bg-ok/10 border border-ok/40 text-ok hover:bg-ok/20 text-[11px] font-semibold transition"><i class="ph-bold ph-download-simple"></i> update</button>' : '') +
      // Scheme allowlist (review nit): esc() blocks attribute breakout but
      // NOT a javascript:/data: scheme. Safe with the built-in GitHub URL,
      // but a future custom/proxied update source must not become XSS.
      '<a href="' + (/^https:\/\//i.test(r.url) ? esc(r.url) : '#') + '" target="_blank" rel="noopener" class="text-ok hover:underline">release notes</a>' +
        (localStorage.getItem('pulsemon_update_dismissed') === r.latest ? '<button onclick="localStorage.removeItem(\'pulsemon_update_dismissed\');renderUpdateUI({running:\'' + escJs(r.running) + '\',latest:\'' + escJs(r.latest) + '\',available:true})" class="text-slate-400 hover:text-white">undo</button>'
          : '<button onclick="localStorage.setItem(\'pulsemon_update_dismissed\',\'' + escJs(r.latest) + '\');renderUpdateUI({running:\'' + escJs(r.running) + '\',latest:\'' + escJs(r.latest) + '\',available:false})" class="text-slate-500 hover:text-white">dismiss</button>') +
      '</span>';
  } else {
    body.innerHTML =
      '<span>running <b class="text-slate-200">' + esc(r.running) + '</b> · up to date</span>' +
      '<span class="text-ok"><i class="ph ph-check-circle"></i> latest</span>';
  }
}

// ---------- Update (one-click on native installs, copy-command on Docker) ----------
// Last release tag reported by /api/update-check; the update button targets it.
let UPDATE_LATEST = null;

async function startUpdate() {
  const target = UPDATE_LATEST;
  if (!target) { setMsg('no update target known — re-check for updates first', 'bad'); return; }
  const btn = $('update-btn');
  if (btn) { btn.disabled = true; btn.classList.add('opacity-50'); }
  if (!confirm('Update pulsemon to ' + target + ' now?\nThe dashboard will be briefly unavailable while the service restarts.')) {
    if (btn) { btn.disabled = false; btn.classList.remove('opacity-50'); }
    return;
  }
  try {
    const res = await api('/api/update', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    if (res.status === 'restarting') {
      await waitForUpdateRestart(target); // ends in location.reload() on success
    } else if (res.status === 'installed') {
      setMsg(res.hint || 'New binary installed — restart the pulsemon service to pick it up.', 'ok');
      checkUpdate(true);
    } else if (res.status === 'container') {
      renderContainerUpdate(res);
    } else if (res.status === 'up-to-date') {
      checkUpdate(true);
    }
  } catch (e) {
    setMsg('update failed: ' + (e.message || e), 'bad');
    if (btn) { btn.disabled = false; btn.classList.remove('opacity-50'); }
  }
}

// Full-screen status shown while the service restarts (or when the wait times
// out). kind: 'work' (spinner) | 'error'.
function updateOverlay(kind, title, sub) {
  let ov = $('update-overlay');
  if (!ov) {
    ov = document.createElement('div');
    ov.id = 'update-overlay';
    ov.className = 'fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm';
    document.body.appendChild(ov);
  }
  const color = kind === 'error' ? 'text-bad' : 'text-warn';
  const icon = kind === 'error' ? 'ph-bold ph-warning-circle' : 'ph ph-spinner animate-spin';
  ov.innerHTML =
    '<div class="flex flex-col items-center gap-3 text-center px-6">' +
      '<i class="' + icon + ' text-4xl ' + color + '"></i>' +
      '<div class="text-[15px] font-semibold text-slate-100">' + esc(title) + '</div>' +
      (sub ? '<div class="text-[12px] font-mono text-slate-400 max-w-[460px] leading-relaxed">' + esc(sub) + '</div>' : '') +
    '</div>';
}
function hideUpdateOverlay() { const ov = $('update-overlay'); if (ov) ov.remove(); }

// The restart 202 is fire-and-forget: the server process dies when systemd
// restarts it, so the only confirmation is healthz answering with the new
// version. Poll it for up to 60s, then reload.
async function waitForUpdateRestart(target) {
  updateOverlay('work', 'Updating to ' + target + '…', 'the service is restarting — this usually takes a few seconds');
  const deadline = Date.now() + 60000;
  for (;;) {
    await new Promise(r => setTimeout(r, 2000));
    let hz = null;
    try { const r = await fetch('/api/healthz'); if (r.ok) hz = await r.json(); } catch (e) { /* still down */ }
    if (hz && hz.version === target) {
      hideUpdateOverlay();
      location.reload();
      return;
    }
    if (Date.now() > deadline) {
      updateOverlay('error', 'Timed out waiting for ' + target,
        'The new binary is installed, but healthz has not confirmed it yet. On the host: <b>journalctl --user -u pulsemon</b> (system-wide: <b>journalctl -u pulsemon</b>). If it failed to start, restore the previous binary and restart the service.');
      return;
    }
  }
}

// Docker install: the app cannot update itself (no docker socket by design).
// Show the operator command (default generic, PULSEMON_UPDATE_CMD override
// server-side) with a copy button in place of the version row.
function renderContainerUpdate(res) {
  const body = $('ver-body');
  if (!body) return;
  const cmd = res.command || 'docker compose up -d --build';
  body.innerHTML =
    '<span class="text-warn"><i class="ph-bold ph-info"></i> Docker install — the app cannot update itself</span>' +
    '<span class="flex items-center gap-2">' +
      '<code class="text-[11px] bg-surface-800 border border-surface-700 rounded px-2 py-0.5">' + esc(cmd) + '</code>' +
      '<button onclick="navigator.clipboard.writeText(\'' + escJs(cmd) + '\').then(() => setMsg(\'command copied\', \'ok\')).catch(() => setMsg(\'copy failed\', \'bad\'))" class="text-slate-400 hover:text-white">copy</button>' +
    '</span>';
}

$('f-tls-cert-file').addEventListener('change', async e => {
  const f = e.target.files[0]; if (!f) return;
  $('tls-cert-file-name').textContent = f.name;
});
$('f-tls-key-file').addEventListener('change', async e => {
  const f = e.target.files[0]; if (!f) return;
  $('tls-key-file-name').textContent = f.name;
});

function renderTLSStatus(t) {
  const badge = $('tls-status');
  const port = $('f-tls-port');
  const rm = $('tls-remove-btn');
  if (!t) { badge.textContent = '—'; return; }
  if (port.value === '') port.value = t.port || 443;
  if (t.enabled) {
    badge.textContent = 'ON · ' + t.port;
    badge.className = 'text-[11px] font-mono px-2 py-0.5 rounded bg-ok/15 border border-ok/40 text-ok';
    rm.disabled = (t.source === 'env');
  } else {
    badge.textContent = 'OFF';
    badge.className = 'text-[11px] font-mono px-2 py-0.5 rounded bg-surface-800 border border-surface-700 text-slate-400';
    rm.disabled = true;
  }
}

async function renderAuthPanel() {
  const badge = $('auth-badge');
  const onBox = $('auth-enabled-box');
  const offBox = $('auth-off-box');
  const status = await api('/api/auth/status').catch(() => ({ enabled: false, authed: false }));
  authState = status;
  if (status.enabled && status.authed) {
    badge.textContent = 'on';
    badge.className = 'px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold border bg-ok/15 border-ok/40 text-ok';
    onBox.classList.remove('hidden');
    offBox.classList.add('hidden');
    $('auth-me').textContent = status.user || '…';
    const users = await api('/api/auth/users').catch(() => []);
    const me = users.find(u => u.username === status.user);
    meIsAdmin = !!(me && me.is_admin);
    // Admin-only surface: user management, alerts, maintenance, TLS and
    // self-update are gated server-side (403 for non-admin sessions);
    // the UI just hides the controls a regular account can't use.
    applyAdminVisibility();
    $('auth-add-user-box').classList.toggle('hidden', !meIsAdmin);
    $('auth-disable-btn').classList.toggle('hidden', !meIsAdmin);
    const list = $('auth-user-list');
    list.innerHTML = (users.length ? users : [{ username: status.user, is_admin: true }]).map(u =>
      '<div class="flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-surface-900 border border-surface-800">' +
      '<span class="text-[12px] font-mono text-slate-200">' + esc(u.username) +
      (u.username === status.user ? ' <span class="text-[10px] text-ok font-mono">(you)</span>' : '') +
      (u.is_admin ? ' <span class="text-[10px] text-amber-400 font-mono">admin</span>' : '') +
      '</span>' +
      (meIsAdmin && u.username !== status.user ? '<button onclick="removeAuthUser(\'' + escJs(u.username) + '\')" class="text-[11px] font-mono text-slate-500 hover:text-bad">Remove</button>' : '') +
      '</div>'
    ).join('');
  } else {
    badge.textContent = 'off';
    badge.className = 'px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold border bg-surface-800 border-surface-700 text-slate-500';
    onBox.classList.add('hidden');
    offBox.classList.remove('hidden');
    // Two "off" states: a fresh install (no account has ever existed)
    // gets the bootstrap button; an operator-disabled install
    // (bootstrapped) refuses unauthenticated account creation
    // server-side, so it shows the CLI re-enable hint instead.
    const wasDisabled = status.bootstrapped === true;
    $('auth-off-desc').textContent = wasDisabled
      ? 'Authentication is off — the dashboard is open to the network.'
      : 'Protect dashboard with secure credential gate.';
    $('auth-create-first-btn').classList.toggle('hidden', wasDisabled);
    $('auth-disabled-note').classList.toggle('hidden', !wasDisabled);
    setUnauthUpdateUI(SETTINGS.allow_unauth_update === true);
  }
}

function openFirstAccountDialog() {
  accountModalMode = 'create';
  $('acc-modal-title').textContent = 'Create Admin Account';$('acc-modal-user-wrap').classList.remove('hidden');
  $('acc-modal-current-wrap').classList.add('hidden');
  $('acc-u').value = '';$('acc-p0').value = '';$('acc-p').value = '';
  $('acc-p2').value = '';$('acc-err').classList.add('hidden');
  $('acc-modal').classList.remove('hidden');$('acc-u').focus();
}

function openChangePasswordDialog() {
  accountModalMode = 'password';
  $('acc-modal-title').textContent = 'Change Password (' + ($('auth-me').textContent || 'User') + ')';
  $('acc-modal-user-wrap').classList.add('hidden');$('acc-modal-current-wrap').classList.remove('hidden');
  $('acc-p0').value = '';$('acc-p').value = '';
  $('acc-p2').value = '';$('acc-err').classList.add('hidden');
  $('acc-modal').classList.remove('hidden');$('acc-p0').focus();
}

async function submitAccountModal() {
  const p0 = $('acc-p0').value;
  const p = $('acc-p').value;
  const p2 = $('acc-p2').value;
  const err = $('acc-err');
  if (accountModalMode === 'password' && p0 === '') { err.textContent = 'Current password is required'; err.classList.remove('hidden'); return; }
  if (p.length < 8) { err.textContent = 'Password must be 8+ characters'; err.classList.remove('hidden'); return; }
  if (p !== p2) { err.textContent = 'Passwords do not match'; err.classList.remove('hidden'); return; }

  try {
    if (accountModalMode === 'create') {
      const u = $('acc-u').value.trim();
      if (!u) { err.textContent = 'Username is required'; err.classList.remove('hidden'); return; }
      await api('/api/auth/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: u, password: p }) });
      await doLogin(u, p);
      setMsg('authentication enabled', 'ok');
    } else {
      const me = (authState && authState.user) || $('auth-me').textContent;
      await api('/api/auth/users/' + encodeURIComponent(me) + '/password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ current_password: p0, password: p }) });
      setMsg('password updated', 'ok');
    }
    $('acc-modal').classList.add('hidden');
    renderAuthPanel();
  } catch (e) {
    err.textContent = e.message;
    err.classList.remove('hidden');
  }
}

async function addAuthUser() {
  const u = $('auth-new-username').value.trim();
  const p = $('auth-new-password').value;
  if (!u || p.length < 8) { setMsg('username and 8+ char password required', 'bad'); return; }
  try {
    await api('/api/auth/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: u, password: p }) });
    $('auth-new-username').value = '';$('auth-new-password').value = '';
    setMsg('account added: ' + u.toLowerCase(), 'ok');
    renderAuthPanel();
  } catch (e) { setMsg('add failed: ' + e.message, 'bad'); }
}

async function removeAuthUser(username) {
  try {
    await api('/api/auth/users/' + encodeURIComponent(username), { method: 'DELETE' });
    setMsg('account removed: ' + username, 'ok');
    renderAuthPanel();
  } catch (e) { setMsg('remove failed: ' + e.message, 'bad'); }
}

async function disableAuth() {
  try {
    await api('/api/auth/disable', { method: 'POST' });
    authState = { enabled: false, authed: false };
    setMsg('authentication disabled', 'ok');
    renderAuthPanel();
  } catch (e) { setMsg('disable failed: ' + e.message, 'bad'); }
}

async function logoutAuth() {
  try { await api('/api/auth/logout', { method: 'POST' }); } catch {}
  location.reload();
}

async function applyTLSCert() {
  const port = parseInt($('f-tls-port').value || '443', 10);
  const certF = $('f-tls-cert-file').files[0];
  const keyF = $('f-tls-key-file').files[0];
  if (!certF || !keyF) { setMsg('select both cert and key files', 'bad'); return; }
  setMsg('applying certificate…', 'ok');
  try {
    const cert = await certF.text();
    const key = await keyF.text();
    const r = await api('/api/settings/tls', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cert, key, port }) });
    renderTLSStatus(r.tls);
    setMsg('cert applied — running on port ' + r.tls.port, 'ok');
  } catch (e) { setMsg('apply failed: ' + e.message, 'bad'); }
}

async function removeTLSCert() {
  setMsg('removing certificate…', 'ok');
  try {
    await api('/api/settings/tls', { method: 'DELETE' });
    renderTLSStatus({ enabled: false, http_addr: location.hostname + ':' + (location.port || '80') });
    setMsg('certificate removed', 'ok');
  } catch (e) { setMsg('remove failed: ' + e.message, 'bad'); }
}

function setMaintUI(on) {
  const btn = $('maint-btn'), icon = $('maint-icon'), txt =$('maint-btn-txt');
  if (on) {
    btn.className = 'px-3 py-1.5 rounded-lg bg-warn/15 border border-warn/40 text-warn text-[12px] font-mono flex items-center gap-1.5 transition';
    icon.className = 'ph-bold ph-play';
    txt.textContent = 'Resume All';
  } else {
    btn.className = 'px-3 py-1.5 rounded-lg bg-surface-800 border border-surface-700 text-slate-300 hover:text-warn text-[12px] font-mono flex items-center gap-1.5 transition';
    icon.className = 'ph-bold ph-pause';
    txt.textContent = 'Pause All';
  }
  $('maint-desc').textContent = on ? 'resume all previously-running probes' : 'pause all active probes globally';
  $('maint-banner').classList.toggle('hidden', !on);
}

let maintBusy = false;
async function toggleMaint() {
  if (maintBusy) return;
  const next = !(SETTINGS.maintenance_mode === true);
  if (next && !SENSORS.some(s => s.state === 'active')) {
    setMsg('no active sensors to pause', 'bad');
    return;
  }
  maintBusy = true;
  setMaintUI(next);
  try {
    const r = await api('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ maintenance_mode: next }) });
    SETTINGS = r;
    setMaintUI(!!r.maintenance_mode);
    setMsg(next ? 'Maintenance Mode active' : 'Maintenance Mode disabled', 'ok');
    await refresh();
  } catch (e) {
    setMaintUI(SETTINGS.maintenance_mode === true);
    setMsg('failed: ' + e.message, 'bad');
  } finally { maintBusy = false; }
}

// allow_unauth_update: opt-in to the in-dashboard self-update button on
// auth-off (trusted-LAN) installs. Only meaningful while auth is off —
// the row lives in the auth-off panel, so this is a no-op when auth is on.
function setUnauthUpdateUI(on) {
  const btn = $('unauth-update-btn'), txt = $('unauth-update-txt');
  if (!btn) return;
  txt.textContent = on ? 'On' : 'Off';
  btn.className = 'px-2.5 py-1 rounded-lg border text-[11px] font-mono shrink-0 transition ' +
    (on ? 'bg-ok/15 border-ok/40 text-ok' : 'bg-surface-800 border-surface-700 text-slate-300');
}
let unauthBusy = false;
async function toggleUnauthUpdate() {
  if (unauthBusy) return;
  const next = !(SETTINGS.allow_unauth_update === true);
  unauthBusy = true;
  setUnauthUpdateUI(next);
  try {
    const r = await api('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ allow_unauth_update: next }) });
    SETTINGS = r;
    setUnauthUpdateUI(!!r.allow_unauth_update);
    setMsg(next ? 'Self-update without an account allowed' : 'Self-update without an account disabled', 'ok');
  } catch (e) {
    setUnauthUpdateUI(SETTINGS.allow_unauth_update === true);
    setMsg('failed: ' + e.message, 'bad');
  } finally { unauthBusy = false; }
}

// Per-scope UNSAVED picks (review nit 2026-10-24): switching tags →
// sensors → tags before pressing Save used to silently re-seed from the
// last-saved SETTINGS.alert_filter, discarding the operator's picks. The
// draft is seeded once from SETTINGS (entries matching sensor ids go to the
// sensors scope, entries matching known tags to the tags scope), survives
// scope switches, and resets after a successful save.
let scopeDraft = null;
function scopeDraftFor(scope) {
  if (!scopeDraft) {
    scopeDraft = { tags: new Set(), sensors: new Set() };
    const tags = new Set(SENSORS.flatMap(s => s.tags || []));
    const ids = new Set(SENSORS.map(s => s.id));
    (SETTINGS.alert_filter || []).forEach(v => {
      if (ids.has(v)) scopeDraft.sensors.add(v);
      else if (tags.has(v)) scopeDraft.tags.add(v);
    });
  }
  return scopeDraft[scope] || new Set();
}

function renderScopeOptions(selected) {
  const scope = $('f-scope').value;
  const box = $('scope-options');
  // No explicit `selected` → render from the draft (the only path that
  // keeps unsaved picks across scope switches).
  const sel = selected ? new Set(selected) : scopeDraftFor(scope);
  if (scope === 'all') { box.innerHTML = '<span class="text-[11px] text-slate-500 font-mono">all sensors trigger alerts</span>'; return; }
  // Structured {val,label}: the old id+'||'+name composite truncated any
  // sensor name containing '||' (a VALID name — review nit).
  const items = scope === 'tags'
    ? [...new Set(SENSORS.flatMap(s => s.tags || []))].map(t => ({ val: t, label: t }))
    : SENSORS.map(s => ({ val: s.id, label: s.name }));
  if (!items.length) { box.innerHTML = '<span class="text-[11px] text-slate-500 font-mono">none available</span>'; return; }
  // data-sel is the selection's source of truth: reading it back from the
  // Tailwind on-class meant any restyle of bg-ok/15 would silently save an
  // EMPTY alert_filter (review nit).
  box.innerHTML = items.map(o => {
    const on = sel.has(o.val);
    return '<button type="button" onclick="toggleScopeItem(this)" data-val="' + esc(o.val) + '" data-sel="' + (on ? '1' : '0') + '" class="px-2 py-0.5 rounded text-[11px] font-mono border transition ' + (on ? 'bg-ok/15 border-ok/40 text-ok' : 'bg-surface-950/60 border-surface-800 text-slate-400 hover:text-white') + '">' + esc(o.label) + '</button>';
  }).join('');
}

function toggleScopeItem(btn) {
  const scope = $('f-scope').value;
  const d = scopeDraftFor(scope);
  const v = btn.dataset.val;
  if (d.has(v)) d.delete(v); else d.add(v);
  renderScopeOptions();
}

function selectedFilterItems() {
  const scope = $('f-scope').value;
  if (scope === 'all') return [];
  return [...document.querySelectorAll('#scope-options [data-val]')].filter(b => b.dataset.sel === '1').map(b => b.dataset.val);
}

function setMsg(text, kind, target) {
  const el = $(target === 'alerts' ? 'alert-msg' : 'set-msg');
  if (!el) return;
  el.textContent = text;
  el.className = 'text-[12px] font-mono px-3 py-2 rounded-lg border ' + (kind === 'bad' ? 'text-bad border-bad/40 bg-bad/5' : 'text-ok border-ok/40 bg-ok/5');
  el.classList.remove('hidden');
}

function renderProviderList(providers) {
  const box = $('provider-list');
  if (!box) return;
  box.innerHTML = '';
  providers.forEach(p => {
    const meta = providerMeta(p.kind);
    const masked = p.url && p.url.includes('***');
    const urlVal = masked ? '' : (p.url || '');
    const isTg = p.kind === 'telegram';
    const isSmtp = p.kind === 'smtp';
    const ex = p.extra || {};
    const chatId = (p.extra && p.extra.chat_id) || '';
    const urlPlaceholder = isTg ? 'Bot endpoint (api.telegram.org/bot…/sendMessage)' : (isSmtp ? 'SMTP host (smtp.example.com)' : 'Webhook URL');
    let extraRow = '';
    if (isTg) {
      extraRow = `
        <div class="mt-1.5 flex items-center gap-2">
          <input id="prov-chatid-telegram" type="text" placeholder="Chat ID (123456789 or @channel)" value="${esc(chatId)}" class="flex-1 bg-surface-950 border border-surface-800 rounded px-2 py-1 text-[12px] font-mono text-slate-200 focus:outline-none focus:border-ok/60" autocomplete="off">
        </div>`;
    } else if (isSmtp) {
      const inp = (id, ph, val, type='text') =>
        `<input id="${id}" type="${type}" placeholder="${ph}" value="${esc(val || '')}" class="flex-1 min-w-0 bg-surface-950 border border-surface-800 rounded px-2 py-1 text-[12px] font-mono text-slate-200 focus:outline-none focus:border-ok/60" autocomplete="off">`;
      const lbl = (t) => `<span class="w-14 shrink-0 text-[10px] uppercase tracking-wide text-slate-500 pt-1">${t}</span>`;
      extraRow = `
        <div class="mt-1.5 space-y-1.5">
          <div class="flex items-center gap-2">${lbl('Port')}${inp('prov-smtp-port','587',ex.port,'number')}</div>
          <div class="flex items-center gap-2">${lbl('From')}${inp('prov-smtp-from','pulsemon@home.lan',ex.from)}</div>
          <div class="flex items-center gap-2">${lbl('To')}${inp('prov-smtp-to','ops@home.lan',ex.to)}</div>
          <div class="flex items-center gap-2">${lbl('User')}${inp('prov-smtp-user','(optional)',ex.username)}</div>
          <div class="flex items-center gap-2">${lbl('Pass')}${inp('prov-smtp-pass','(app password)',ex.password,'password')}</div>
          <div class="flex items-center gap-2">${lbl('TLS')}
            <select id="prov-smtp-tls" class="flex-1 bg-surface-950 border border-surface-800 rounded px-2 py-1 text-[12px] font-mono text-slate-200 focus:outline-none focus:border-ok/60">
              <option value="auto" ${ex.tls_mode==='auto'?'selected':''}>auto (465 TLS / else STARTTLS)</option>
              <option value="starttls" ${ex.tls_mode==='starttls'?'selected':''}>STARTTLS</option>
              <option value="tls" ${ex.tls_mode==='tls'?'selected':''}>implicit TLS</option>
              <option value="none" ${ex.tls_mode==='none'?'selected':''}>none (plaintext)</option>
            </select>
          </div>
        </div>`;
    }
    const row = document.createElement('div');
    row.className = 'border border-surface-800 rounded-lg px-3 py-2 bg-surface-950/50';
    row.innerHTML = `
      <div class="flex items-center justify-between mb-1.5">
        <span class="text-[12px] font-semibold text-slate-200 flex items-center gap-1.5">${meta.icon} ${esc(meta.name)}</span>
        <button type="button" onclick="toggleProvider('${escJs(p.kind)}')" class="px-2 py-0.5 rounded text-[11px] font-mono border transition ${p.enabled ? 'bg-ok/15 border-ok/40 text-ok' : 'bg-surface-800 border-surface-700 text-slate-400'}">
          ${p.enabled ? 'Enabled' : 'Disabled'}
        </button>
      </div>
      <div class="flex items-center gap-2">
        <input id="prov-url-${esc(p.kind)}" type="text" placeholder="${urlPlaceholder}" value="${esc(urlVal)}" class="flex-1 bg-surface-950 border border-surface-800 rounded px-2 py-1 text-[12px] font-mono text-slate-200 focus:outline-none focus:border-ok/60" autocomplete="off">
        <button type="button" onclick="testWebhook('${escJs(p.kind)}')" class="px-2.5 py-1 rounded bg-jit/10 border border-jit/30 text-jit hover:bg-jit/20 text-[11px] font-semibold whitespace-nowrap">Test</button>
      </div>
      ${extraRow}`;
    box.appendChild(row);
  });
  updateSetSummary();
}

function updateSetSummary() {
  const el = $('set-summary');
  if (!el || !SETTINGS || !SETTINGS.providers) return;
  const active = SETTINGS.providers.filter(p => p.enabled && p.has_url);
  el.textContent = active.length ? active.map(p => providerMeta(p.kind).name).join(', ') : 'no active destinations';
}

async function toggleProvider(kind) {
  const p = (SETTINGS.providers || []).find(x => x.kind === kind); if (!p) return;
  try {
    const r = await api('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ providers: [{ kind, enabled: !p.enabled }] }) });
    SETTINGS = r;
    renderProviderList(r.providers || []);
  } catch (e) { setMsg(e.message, 'bad', 'alerts'); }
}

async function saveAlerts() {
  const body = {
    alert_scope: $('f-scope').value,
    alert_filter: selectedFilterItems(),
    realert_min: +$('f-realert').value
  };
  body.providers = (SETTINGS.providers || []).filter(p => {
    // id is rendered esc()'d (see renderProviders) — read back the same
    // transform so the lookup stays symmetric for any kind value.
    const input = $('prov-url-' + esc(p.kind));
    return input && input.value.trim() !== '';
  }).map(p => {
    const pb = { kind: p.kind, url: $('prov-url-' + esc(p.kind)).value.trim() };
    if (p.kind === 'telegram') {
      const ci = $('prov-chatid-telegram');
      pb.extra = { chat_id: ci ? ci.value.trim() : '' };
    }
    if (p.kind === 'smtp') {
      // host is NOT sent here: it travels in pb.url, where the server
      // validates it against the reserved-range blocklist (validateSMTPHost).
      pb.extra = {
        port:     val('prov-smtp-port'),
        from:     val('prov-smtp-from'),
        to:       val('prov-smtp-to'),
        username: val('prov-smtp-user'),
        password: val('prov-smtp-pass'),
        tls_mode: sel('prov-smtp-tls')
      };
    }
    return pb;
  });

  try {
    const r = await api('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    SETTINGS = r;
    scopeDraft = null; // saved — re-seed the draft from the server on next open
    renderProviderList(r.providers || []);
    setMsg('alerts saved', 'ok', 'alerts');
  } catch (e) { setMsg(e.message, 'bad', 'alerts'); }
}

async function testWebhook(kind) {
  try {
    const r = await api('/api/settings/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ kind }) });
    setMsg(r.ok ? '✓ ' + r.detail : r.detail, r.ok ? 'ok' : 'bad', 'alerts');
  } catch (e) { setMsg(e.message, 'bad', 'alerts'); }
}

// ---------- Inspector & Charting ----------
async function openInspector(id) {
  inspectId = id;
  $('insp-backdrop').classList.remove('hidden');
  await loadInspector();
}
function closeInspector() { inspectId = null; $('insp-backdrop').classList.add('hidden'); }

async function clearHistory() {
  const id = inspectId; if (!id) return;
  try {
    await api('/api/sensors/' + id + '/history', { method: 'DELETE' });
    toast('history purged', 'ok');
    await Promise.all([refresh(), loadInspector()]);
  } catch (e) { toast('failed: ' + e.message, 'bad'); }
}

function renderGraph(el, data) {
  const pts = (data.points || []).filter(p => p.total > 0);
  if (!pts.length) {
    el.innerHTML = '<div class="flex items-center justify-center h-28 text-[12px] text-slate-600 font-mono">no probe entries in this window</div>';
    return;
  }
  const W = Math.max(el.clientWidth || 0, 320), H = 120;
  const padL = 40, padR = 8, padT = 8, padB = 16;
  const maxAvg = Math.max(...pts.map(p => p.avg || 0), 20);
  const top = Math.max(40, Math.ceil(maxAvg * 1.1 / 40) * 40);

  const x = i => padL + (i / Math.max(pts.length - 1, 1)) * (W - padL - padR);
  const y = v => padT + (1 - v / top) * (H - padT - padB);

  // One subpath per CONTIGUOUS run of non-null buckets (review 2026-10-24):
  // AVG(rtt_ms) is NULL for an all-lost bucket (it survives the Total>0
  // filter), and the old single-path builder emitted 'L' when pts[0].avg was
  // null — SVG discards everything before the first moveto, so the whole
  // graph rendered NOTHING exactly at outage onset, the moment an operator
  // opens the inspector. Gaps also used to be bridged as if service had
  // continued. Multiple M…L subpaths in one d are valid SVG.
  const runs = [];
  let cur = null;
  pts.forEach((p, i) => {
    if (p.avg == null) { cur = null; return; }
    const pt = x(i).toFixed(1) + ' ' + y(p.avg).toFixed(1);
    if (cur) { cur.d += ' L' + pt; cur.last = i; }
    else { cur = { first: i, last: i, d: 'M' + pt }; runs.push(cur); }
  });
  const path = runs.map(r => r.d).join(' ');
  const area = runs.filter(r => r.last > r.first)
    .map(r => r.d + ' L' + x(r.last).toFixed(1) + ' ' + (H - padB) + ' L' + x(r.first).toFixed(1) + ' ' + (H - padB) + ' Z')
    .join(' ');

  const axis = [0, 0.5, 1].map(f => {
    const v = Math.round(top * f), yy = y(v).toFixed(1);
    return '<line x1="' + padL + '" y1="' + yy + '" x2="' + (W - padR) + '" y2="' + yy + '" stroke="var(--g-grid)" stroke-width="1"/>' +
      '<text x="' + (padL - 4) + '" y="' + (y(v) + 3).toFixed(1) + '" font-size="9" fill="var(--g-text)" font-family="JetBrains Mono" text-anchor="end">' + v + 'ms</text>';
  }).join('');

  const ticks = pts.map((p, i) => p.lost > 0
    ? '<line x1="' + x(i).toFixed(1) + '" y1="' + (H - padB) + '" x2="' + x(i).toFixed(1) + '" y2="' + (H - padB + 6) + '" stroke="var(--bad-solid)" stroke-width="2"/>'
    : '').join('');

  const t0 = new Date(pts[0].t * 1000), t1 = new Date(pts[pts.length - 1].t * 1000);
  const fmtT = t => t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });

  el.innerHTML =
    '<svg viewBox="0 0 ' + W + ' ' + H + '" width="' + W + '" height="' + H + '" class="w-full">' +
      '<path d="' + area + '" fill="var(--ok-solid)" opacity="0.12"/>' +
      '<path d="' + path + '" fill="none" stroke="var(--ok-solid)" stroke-width="1.5"/>' +
      axis + ticks +
      '<text x="' + padL + '" y="' + (H - 2) + '" font-size="9" fill="var(--g-text)" font-family="JetBrains Mono">' + fmtT(t0) + '</text>' +
      '<text x="' + (W - padR) + '" y="' + (H - 2) + '" font-size="9" fill="var(--g-text)" font-family="JetBrains Mono" text-anchor="end">' + fmtT(t1) + '</text>' +
    '</svg>';
}

async function loadInspector() {
  if (!inspectId) return;
  try {
    const [s, g] = await Promise.all([api('/api/sensors/' + inspectId), api('/api/sensors/' + inspectId + '/graph?range=' + graphRange)]);
    const m = statusMeta(s);
    $('insp-icon').className = 'ph-bold ' + m.icon + ' text-[20px] shrink-0 mt-0.5 ' + (m.label === 'PAUSED' ? 'text-slate-500' : m.label === 'UP' ? 'text-ok' : m.label === 'WARN' ? 'text-warn' : 'text-bad');
    $('insp-name').textContent = s.name;
    $('insp-tag').textContent = (s.tags && s.tags.length) ? s.tags.join(' · ') : '—';
    $('insp-target').textContent = s.target + (s.state === 'paused' ? ' (PAUSED)' : '');$('insp-interval').textContent = s.interval_s + 's interval · ' + s.timeout_ms + 'ms timeout · loss ' + s.loss_warn + '%';

    const g1 = $('grange-1h'), g2 =$('grange-24h');
    if (g1) g1.className = 'px-2 py-0.5 rounded text-[11px] font-mono border ' + (graphRange === '1h' ? 'border-ok/40 bg-ok/10 text-ok' : 'border-surface-800 text-slate-400');
    if (g2) g2.className = 'px-2 py-0.5 rounded text-[11px] font-mono border ' + (graphRange === '24h' ? 'border-ok/40 bg-ok/10 text-ok' : 'border-surface-800 text-slate-400');

    $('insp-graph-up').textContent = g.total ? (g.uptime_pct >= 100 ? '100%' : g.uptime_pct.toFixed(2) + '%') + ' uptime' : 'no data';
    renderGraph($('insp-graph'), g);

    const st = s.stats;
    $('insp-rtt').textContent = st && st.rtt_last != null ? fmtRtt(st.rtt_last) : '—';
    const certEl = $('insp-cert');
    const cert = certNote(s);
    if (cert) { certEl.innerHTML = cert; certEl.classList.remove('hidden'); } else certEl.classList.add('hidden');

    $('insp-minavgmax').textContent = (st && st.rtt_min != null) ? fmtRtt(st.rtt_min) + ' / ' + fmtRtt(st.rtt_avg) + ' / ' + fmtRtt(st.rtt_max) : '—';
    $('insp-loss').textContent = st ? st.loss_pct.toFixed(1) + '%' : '—';
    $('insp-loss').className = 'text-[16px] font-bold mt-1 ' + (st && st.loss_pct > 0 ? 'text-warn' : 'text-ok');$('insp-losssub').textContent = st ? st.lost_count + ' / ' + st.total + ' dropped' : '';
    const j = jitterOf(s); $('insp-jitter').textContent = j != null ? '±' + fmtRtt(j) : '—';
  } catch (e) { console.error(e); }
}

let toastTimer = null;
function toast(msg, kind) {
  let el = $('toast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast';
    document.body.appendChild(el);
  }
  const color = kind === 'bad' ? 'text-bad border-bad/40 bg-surface-900' : 'text-ok border-ok/40 bg-surface-900';
  el.className = 'fixed bottom-5 left-1/2 -translate-x-1/2 z-[60] px-4 py-2 rounded-lg border text-[12px] font-mono shadow-2xl ' + color;
  el.textContent = msg;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.remove(), 2500);
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    closeModal();
    closeInspector();
    closeSettings();
    const acc = $('acc-modal');
    if (acc) acc.classList.add('hidden');
  }
});

(async function boot() {
  const ok = await checkAuth();
  if (ok) startPolling();
})();

let _pollStarted = false;
function startPolling() {
  // Idempotent: boot() arms it for already-authenticated page loads and
  // doLogin() arms it after a successful login (review 2026-10-24: the
  // login path used to never call startPolling, leaving every
  // auth-enabled dashboard a frozen snapshot until a manual reload).
  if (_pollStarted) return;
  _pollStarted = true;
  refresh();
  refreshAdminState();
  // Gate the 5s pollers on tab visibility: a hidden tab's polls are pure
  // server cost (each refresh re-scans stats on the backend, external review
  // F4) with no viewer to show them to (2026-10-23 external review F14). The
  // timers keep ticking (a cheap visibility check each tick) and the poll is
  // simply skipped while hidden; on return, visibilitychange fires an
  // immediate refresh so the data is fresh the moment the tab is shown again.
  setInterval(() => { if (document.visibilityState === 'visible') refresh(); }, 5000);
  let _sparkRt; window.addEventListener('resize', () => { clearTimeout(_sparkRt); _sparkRt = setTimeout(layoutSparklines, 120); });
  setInterval(() => { if (document.visibilityState === 'visible' && inspectId) loadInspector(); }, 5000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      refresh();
      if (inspectId) loadInspector();
    }
  });
  checkUpdate(false);                    // initial update check
  setInterval(() => checkUpdate(false), 10 * 60 * 1000);  // re-check every 10 min (backend caches 30)
}
