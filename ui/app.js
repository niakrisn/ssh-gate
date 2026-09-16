// ssh-gate Web UI: polls /api/connections every 2.5 s, tabs,
// search (300 ms debounce), server-side pagination.

const PAGE_SIZE = 50;
const POLL_MS = 2500;
const SEARCH_DEBOUNCE_MS = 300;

const STATUS_LABEL = {
  active: 'Активно',
  dialing: 'Подключение',
  closed: 'Закрыто',
  error: 'Ошибка',
};

const PROTO_LABEL = { socks5: 'SOCKS5', http: 'HTTP', mtproto: 'MTProto' };

const state = { tab: 'active', page: 1, q: '', proto: '' };

const $ = (id) => document.getElementById(id);

function apiParams() {
  const p = new URLSearchParams({
    tab: state.tab,
    page: String(state.page),
    page_size: String(PAGE_SIZE),
  });
  if (state.q) p.set('q', state.q);
  if (state.proto) p.set('proto', state.proto);
  return p;
}

async function fetchPage(params) {
  const res = await fetch('/api/connections?' + params);
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res.json();
}

function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(1) + ' ' + units[i];
}

function fmtDuration(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + ' с';
  const m = Math.floor(s / 60);
  if (m < 60) return m + ' мин ' + (s % 60) + ' с';
  const h = Math.floor(m / 60);
  return h + ' ч ' + (m % 60) + ' мин';
}

function fmtStarted(unix) {
  return new Date(unix * 1000).toLocaleTimeString('ru-RU');
}

// IPv6 адреса обёртываются в квадратные скобки: [2001:db8::1]:443
function fmtAddr(ip, port) {
  return ip.includes(':') ? '[' + ip + ']:' + port : ip + ':' + port;
}

function render(data) {
  const rows = data.items;
  const tbody = $('table').querySelector('tbody');
  tbody.innerHTML = '';
  for (const it of rows) {
    const tr = document.createElement('tr');
    const cells = [
      it.proto || '—',
      it.src || '—',
      '', // назначение — отдельная отрисовка ниже: IP + hostname
      STATUS_LABEL[it.status] || it.status,
      fmtStarted(it.started_at),
      fmtDuration(it.duration_ms),
      fmtBytes(it.bytes_up),
      fmtBytes(it.bytes_down),
      it.reason || '',
    ];
    cells.forEach((c, i) => {
      const td = document.createElement('td');
      if (i === 2) { // назначение: всегда IP, hostname в скобках при наличии
        if (it.dst_ip) {
          td.textContent = fmtAddr(it.dst_ip, it.port);
          if (it.host && it.host !== it.dst_ip) {
            const name = document.createElement('span');
            name.className = 'dest-name';
            name.textContent = ' (' + it.host + ')';
            td.appendChild(name);
          }
        } else {
          td.textContent = fmtAddr(it.host, it.port);
        }
        td.className = 'dest';
      } else if (i === 3) { // status renders as a colored dot
        const span = document.createElement('span');
        span.className = 'status ' + it.status;
        span.textContent = c;
        td.appendChild(span);
      } else {
        td.textContent = c;
      }
      if (i === 1) {
        td.className = 'mono';
      } else if (i === 5 || i === 6 || i === 7) {
        td.className = 'num';
      }
      if (i === 8 && c) td.title = c;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  }

  const hasRows = rows.length > 0;
  $('table').style.display = hasRows ? '' : 'none';
  $('empty').hidden = hasRows;

  const pages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));
  $('page-info').textContent = 'стр. ' + state.page + ' из ' + pages + ' · всего ' + data.total;
  $('prev').disabled = state.page <= 1;
  $('next').disabled = state.page >= pages;
}

// refresh loads the current tab; if the page became empty (history pruned),
// it steps back to the last non-empty page.
async function refresh() {
  try {
    const data = await fetchPage(apiParams());
    const pages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));
    if (state.page > pages) {
      state.page = pages;
      return refresh();
    }
    render(data);
    refreshHistoryCount();
  } catch (e) {
    // polling: skip errors silently, the next tick retries.
  }
}

async function refreshHistoryCount() {
  try {
    const d = await fetchPage(new URLSearchParams({ tab: 'history', page: '1', page_size: '1' }));
    $('history-count').textContent = d.total > 0 ? '(' + d.total + ')' : '';
  } catch (e) {
    // the badge is not critical.
  }
}

function selectTab(tab) {
  document.querySelectorAll('.tab').forEach((b) => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });
  state.tab = tab;
  state.page = 1;
  refresh();
}

document.querySelectorAll('.tab').forEach((btn) => {
  btn.addEventListener('click', () => selectTab(btn.dataset.tab));
});

$('prev').addEventListener('click', () => {
  if (state.page > 1) { state.page--; refresh(); }
});
$('next').addEventListener('click', () => {
  state.page++;
  refresh();
});

// status line: SSH endpoint, probe result, active connections per protocol.
async function refreshStatus() {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) return;
    renderStatus(await res.json());
  } catch (e) {
    // polling: skip errors silently, the next tick retries.
  }
}

function renderStatus(s) {
  const ssh = s.ssh || {};
  const dotState = !ssh.reachable ? 'err' : ssh.connected ? 'ok' : 'warn';
  $('ssh-dot').className = 'dot ' + dotState;
  let info = ssh.host + ':' + ssh.port + ' · ';
  info += ssh.reachable ? ssh.rtt_ms + ' мс · ' : 'недоступен · ';
  info += ssh.connected ? 'SSH-сессия активна' : 'SSH-сессия не подключена';
  $('ssh-info').textContent = info;

  const parts = [];
  for (const [p, n] of Object.entries(s.active || {})) {
    if (n > 0) parts.push((PROTO_LABEL[p] || p) + ' ' + n);
  }
  $('active-summary').textContent = parts.length ? 'Активные: ' + parts.join(' · ') : 'Активных нет';
}

document.querySelector('.search').addEventListener('submit', (e) => e.preventDefault());

$('proto').addEventListener('change', (e) => {
  state.proto = e.target.value;
  state.page = 1;
  refresh();
});

let debounceTimer;
$('q').addEventListener('input', (e) => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    state.q = e.target.value.trim();
    state.page = 1;
    refresh();
  }, SEARCH_DEBOUNCE_MS);
});

setInterval(() => { refresh(); refreshStatus(); }, POLL_MS);
refresh();
refreshStatus();
