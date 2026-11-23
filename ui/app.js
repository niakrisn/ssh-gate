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

const PROTO_LABEL = { socks5: 'SOCKS5', http: 'HTTP' };

// SSH transport states from /api/status.
const TUNNEL_LABEL = {
  connected: 'подключён',
  connecting: 'подключение',
  reconnecting: 'переподключение',
  key_rejected: 'VPS не принимает ключ: добавьте ssh_key.pub в authorized_keys',
  unreachable: 'SSH-сессия не подключена',
  host_key_mismatch: 'ключ хоста изменился',
  ssh_error: 'ошибка SSH',
  healthy: 'работает',
  checking: 'проверка',
  excluded: 'исключён',
  disconnected: 'нет соединения',
};

const state = { tab: 'active', page: 1, q: '', proto: '' };

const $ = (id) => document.getElementById(id);

const stateLabel = (name) => TUNNEL_LABEL[name] || name || 'неизвестно';

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

// Согласование существительного с числительным: 1 туннель, 2 туннеля, 5 туннелей.
function plural(n, one, few, many) {
  const ten = n % 10, hundred = n % 100;
  if (ten === 1 && hundred !== 11) return one;
  if (ten >= 2 && ten <= 4 && (hundred < 12 || hundred > 14)) return few;
  return many;
}

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

function fmtUptime(s) {
  if (s < 60) return s + ' с';
  const m = Math.floor(s / 60);
  if (m < 60) return m + ' мин';
  const h = Math.floor(m / 60);
  if (h < 24) return h + ' ч ' + (m % 60) + ' мин';
  const d = Math.floor(h / 24);
  return d + ' д ' + (h % 24) + ' ч';
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
        if (it.server_id) {
          const path = document.createElement('span');
          path.className = 'dest-name';
          path.textContent = ' · SSH ' + it.server_id + '/#' + it.transport;
          td.appendChild(path);
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
    lastStatus = await res.json();
    renderStatus(lastStatus);
  } catch (e) {
    // polling: skip errors silently, the next tick retries.
  }
}

// DNS row: answers and failures per SSH server and resolver.
function renderDNS(dns) {
  $('dns-row').hidden = !dns;
  if (!dns) return;
  $('dns-dot').className = 'dot ' + (dns.degraded ? 'warn' : 'ok');
  const resolverLabel = (srv) => srv.server_id ? srv.server_id + ' / ' + srv.name : srv.name;
  const parts = dns.servers.map((srv) => {
    const label = resolverLabel(srv);
    if (srv.ok + srv.fail === 0) return label + ' не использовался';
    let p = label;
    if (srv.paused) p += ' · пауза';
    if (srv.last_ok_at > 0) p += ' · ' + srv.rtt_ms + ' мс';
    if (srv.fail > 0) p += ' · ошибок ' + srv.fail + ' из ' + (srv.ok + srv.fail);
    return p;
  });
  $('dns-info').textContent = 'DNS: ' + parts.join(' · ');
  // last error of each server, full text
  $('dns-info').title = dns.servers.filter((srv) => srv.error).map((srv) => resolverLabel(srv) + ': ' + srv.error).join('\n');
}

// --- детализация по SSH-серверам -------------------------------------------
//
// Квоты показаны полосами занятости: абсолютное число без ёмкости не читается,
// 99 из 8192 и 99 из 128 — это разные ситуации. TCP-счётчики транспорта свёрнуты,
// пока транспорт спокоен, и раскрываются сами при росте retrans или RTT, при
// ошибке, при потере соединения — и вручную по клику.

// Клик закрепляет состояние строки: иначе шумный транспорт, который оператор
// свернул, развернулся бы обратно на следующем полле.
const tcpPinned = new Map();
let tcpPrev = new Map();
let lastStatus = null;

// Ретрансмисции считаются с момента connect, поэтому само число ни о чём не
// говорит — важно, что оно приросло с прошлого полла. Уменьшение означает
// переподключение транспорта, а не улучшение.
function tcpGrew(prev, tcp) {
  if (!prev || !tcp) return false;
  if (tcp.total_retrans > prev.retrans) return true;
  return tcp.rtt_ms > prev.rtt * 1.5 + 0.1;
}

function quotaRow(name, hint, used, limit, extra) {
  used = used || 0;
  limit = limit || 0;
  const row = el('div', 'quota');
  const label = el('span', 'quota-name', name);
  label.title = hint;
  row.appendChild(label);
  const pct = limit > 0 ? (used / limit) * 100 : 0;
  const bar = el('span', 'bar');
  const fill = el('i', pct >= 95 ? 'err' : pct >= 80 ? 'warn' : 'ok');
  // Ширина ставится всегда: без этого незаполненная полоса растягивается на
  // весь блок и пустой лимит выглядит как исчерпанный.
  fill.style.width = (used > 0 ? Math.max(pct, 2) : 0) + '%';
  bar.appendChild(fill);
  row.appendChild(bar);
  const value = el('span', 'quota-num', used + '/' + limit + ' · ' +
    (used > 0 && pct < 1 ? '<1' : Math.round(pct)) + '%');
  if (extra) value.appendChild(el('em', null, ' · ' + extra));
  row.appendChild(value);
  return row;
}

function healthRow(server) {
  const h = server.health || {};
  const row = el('div', 'quota');
  const label = el('span', 'quota-name', 'доступность');
  label.title = (h.url || '') + ' — запрос идёт через свежий канал SSH, из сети SSH-сервера';
  row.appendChild(label);
  const value = el('span', 'quota-num wide ' + (h.last_error ? 'bad' : 'ok'),
    (h.last_error ? '✗ ' : '✓ ') + (h.successes || 0) + '/' + (h.success_limit || 0) +
    (h.failures ? ' · ошибок ' + h.failures : ''));
  if (server.checked_at) value.appendChild(el('em', null, ' · ' + fmtStarted(server.checked_at)));
  if (h.excluded_until && h.excluded_until * 1000 > Date.now()) {
    value.appendChild(el('em', 'warn', ' · исключён до ' + fmtStarted(h.excluded_until)));
  }
  row.appendChild(value);
  return row;
}

function slotRow(server, slot, prev) {
  const key = server.id + '/' + slot.slot;
  const expandable = !!slot.tcp;
  const open = tcpPinned.has(key) ? tcpPinned.get(key)
    : !slot.connected || !!slot.error || tcpGrew(prev, slot.tcp);
  const btn = el('button', 'slot' + (slot.connected ? '' : ' bad'));
  btn.type = 'button';
  btn.dataset.tcpKey = key;
  btn.disabled = !expandable;
  btn.setAttribute('aria-expanded', expandable && open ? 'true' : 'false');
  btn.appendChild(el('span', 'chev', expandable ? (open ? '▾' : '▸') : '·'));
  btn.appendChild(el('span', 'slot-id', '#' + slot.slot));
  btn.appendChild(el('span', 'slot-state', stateLabel(slot.state)));
  const n = slot.active_channels || 0;
  btn.appendChild(el('span', 'slot-load', n + ' ' + plural(n, 'подключение', 'подключения', 'подключений')));
  if (slot.state === 'host_key_mismatch') {
    const advice = 'Независимо проверьте новый отпечаток, затем замените только запись ' + server.id + ' в ssh_known_hosts и перезапустите службу.';
    btn.appendChild(el('span', 'slot-error', [slot.error, advice].filter(Boolean).join(' ')));
  } else if (slot.error) {
    btn.appendChild(el('span', 'slot-error', slot.error));
  }
  if (expandable && open) {
    const t = slot.tcp;
    const grew = prev ? t.total_retrans - prev.retrans : 0;
    let text = 'RTT ' + t.rtt_ms.toFixed(2) + '/' + t.min_rtt_ms.toFixed(2) + ' мс · retrans ' + t.total_retrans;
    if (grew > 0) text += ' (+' + grew + ')';
    text += ' · ↑' + fmtBytes(t.bytes_sent) + ' ↓' + fmtBytes(t.bytes_received);
    const tcp = el('span', 'slot-tcp', text);
    tcp.title = 'rttvar ' + t.rttvar_ms + ' мс · cwnd ' + t.cwnd +
      (typeof t.last_data_recv_s === 'number' ? ' · последние данные ' + t.last_data_recv_s.toFixed(1) + ' с назад' : '');
    btn.appendChild(tcp);
  }
  const li = el('li');
  li.appendChild(btn);
  return li;
}

function renderServers(servers) {
  const box = $('server-detail');
  // Блоки пересобираются на каждый полл, поэтому фокус возвращается той же
  // строке транспорта — иначе клик по раскрытию теряется через 2,5 с.
  const active = document.activeElement;
  const focusKey = active && active.dataset ? active.dataset.tcpKey : '';
  box.innerHTML = '';
  const seen = new Map();
  servers.forEach((server) => {
    const limits = server.limits || {};
    const health = server.health || {};
    const section = el('section', 'server');
    if (servers.length > 1) section.appendChild(el('h2', 'server-id', server.id));
    const quotas = el('div', 'quotas');
    quotas.appendChild(quotaRow('подключения', 'Клиентские подключения, обслуживаемые через этот SSH-сервер, из его лимита',
      limits.client_tunnels_in_use, limits.client_tunnels));
    quotas.appendChild(quotaRow('открываются', 'Клиентские channel open в ожидании: назначение ещё не принято или отваливается по таймауту самого SSH-сервера',
      limits.pending_opens_in_use, limits.pending_opens));
    // Канал без клиентского подключения за спиной — это tunnel DNS и HTTPS-проба
    // на том же транспорте. Оба счётчика читаются не одним атомарным действием,
    // поэтому отрицательная разница возможна и означает гонку, а не утечку.
    const service = Math.max(0, (server.active_channels || 0) - (limits.client_tunnels_in_use || 0));
    quotas.appendChild(quotaRow('DNS и проверка', 'DNS-запросы и HTTPS-проба, ожидающие channel open; плюс — уже открытые служебные каналы',
      limits.service_opens_in_use, limits.service_opens, '+' + service + ' служебных'));
    quotas.appendChild(healthRow(server));
    section.appendChild(quotas);
    if (server.reason) section.appendChild(el('p', 'note', server.reason));
    if (health.last_error) section.appendChild(el('p', 'note', 'проверка: ' + health.last_error));
    const list = el('ul', 'slots');
    for (const slot of server.transports || []) {
      const key = server.id + '/' + slot.slot;
      list.appendChild(slotRow(server, slot, tcpPrev.get(key)));
      if (slot.tcp) seen.set(key, { retrans: slot.tcp.total_retrans, rtt: slot.tcp.rtt_ms });
    }
    section.appendChild(list);
    box.appendChild(section);
  });
  tcpPrev = seen;
  box.hidden = box.children.length === 0;
  if (focusKey) {
    const again = box.querySelector('.slot[data-tcp-key="' + CSS.escape(focusKey) + '"]');
    if (again) again.focus();
  }
}

$('server-detail').addEventListener('click', (e) => {
  const btn = e.target.closest('.slot');
  if (!btn || btn.disabled) return;
  tcpPinned.set(btn.dataset.tcpKey, btn.getAttribute('aria-expanded') !== 'true');
  if (lastStatus) renderServers((lastStatus.ssh || {}).servers || []);
});

function renderStatus(s) {
  const ssh = s.ssh || {};
  const servers = ssh.servers || [];
  if (servers.length === 0) {
    $('ssh-dot').className = 'dot warn';
    $('ssh-info').textContent = 'SSH-серверы не заданы · доступны прямые маршруты · работает ' + fmtUptime(s.uptime_s);
    $('server-detail').hidden = true;
    $('dns-row').hidden = true;
    const directActive = Object.entries(s.active || {}).filter(([, n]) => n > 0).map(([p, n]) => (PROTO_LABEL[p] || p) + ' ' + n);
    $('active-summary').textContent = directActive.length ? 'Активные: ' + directActive.join(' · ') : 'Активных нет';
    $('active-count').textContent = s.active_total > 0 ? '(' + s.active_total + ')' : '';
    return;
  }
  const dotState = ssh.eligible ? 'ok' : ssh.connected ? 'warn' : 'err';
  $('ssh-dot').className = 'dot ' + dotState;
  $('ssh-info').textContent = servers.map((server) => {
    const connected = (server.transports || []).filter((slot) => slot.connected).length;
    const slots = (server.transports || []).length;
    return server.id + ' · ' + server.address + ' · ' + stateLabel(server.state) + ' · транспорты ' + connected + '/' + slots;
  }).join(' | ') + ' · работает ' + fmtUptime(s.uptime_s);
  // A transport can fail while the server still serves traffic, and then
  // server.reason stays empty; the tooltip falls back to the slot's own error.
  const slotError = (server) => (server.transports || []).map((slot) => slot.error).find(Boolean) || '';
  $('ssh-info').title = servers.map((server) => server.id + ': ' + (server.reason || slotError(server) || 'нет ошибок')).join('\n');
  renderDNS(s.dns);

  // Квоты и транспорты по каждому серверу.
  renderServers(servers);

  const parts = [];
  for (const [p, n] of Object.entries(s.active || {})) {
    if (n > 0) parts.push((PROTO_LABEL[p] || p) + ' ' + n);
  }
  $('active-summary').textContent = parts.length ? 'Активные: ' + parts.join(' · ') : 'Активных нет';
  $('active-count').textContent = s.active_total > 0 ? '(' + s.active_total + ')' : '';
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
