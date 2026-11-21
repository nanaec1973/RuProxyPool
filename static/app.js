'use strict';
// Дашборд строится только через DOM API (textContent), без innerHTML с данными:
// значения из внешних источников (провайдер, город) не могут внедрить HTML/JS.

let currentTarget = '';
let currentProxies = [];
let targetsMeta = [];

const $ = (id) => document.getElementById(id);

function el(tag, opts, children) {
  const node = document.createElement(tag);
  if (opts) {
    if (opts.cls) node.className = opts.cls;
    if (opts.text !== undefined) node.textContent = String(opts.text);
    if (opts.colspan) node.colSpan = opts.colspan;
  }
  (children || []).forEach((c) => node.appendChild(c));
  return node;
}

function fmt(n) { return (n || 0).toLocaleString('ru-RU'); }

function getToken() {
  try { return sessionStorage.getItem('adminToken') || ''; } catch (e) { return ''; }
}
function saveToken(v) {
  try { sessionStorage.setItem('adminToken', v); } catch (e) { /* хранилище недоступно */ }
}

async function loadAll() {
  try {
    const st = await (await fetch('/api/stats')).json();
    targetsMeta = st.targets_meta || [];

    $('lblRaw').textContent = 'Проанализировано (' + (st.sources_count || 0) + ' источников)';
    $('stRaw').textContent = fmt(st.raw_analyzed);
    $('stForeign').textContent = fmt(st.foreign_filtered);
    $('stTotal').textContent = fmt(st.total_candidates);
    $('stScanned').textContent = fmt(st.scanned_count);
    $('stAlive').textContent = fmt(st.healthy_count) + ' / ' + fmt(st.alive_count);

    const pct = st.total_candidates > 0 ? Math.min(100, Math.round((st.scanned_count / st.total_candidates) * 100)) : 0;
    $('progressFill').style.width = pct + '%';
    $('progressPercent').textContent = pct + '%';
    $('progressText').textContent = st.scan_in_progress
      ? '🔍 Идет сканирование (' + st.scanned_count + ' из ' + st.total_candidates + ')...'
      : (st.recheck_in_progress ? '♻️ Перепроверка живых прокси...' : '✅ Сканирование завершено. Авто-обновление активно.');

    $('adminState').textContent = st.admin_enabled
      ? 'Служебные действия требуют токен.'
      : 'Служебные действия отключены: на сервере не задан ADMIN_TOKEN.';

    renderFilters(st);

    const url = currentTarget ? '/api/proxies?target=' + encodeURIComponent(currentTarget) : '/api/proxies';
    const prData = await (await fetch(url)).json();
    currentProxies = prData.proxies || [];
    renderTable(currentProxies);
  } catch (e) {
    console.error(e);
  }
}

function renderFilters(st) {
  const bar = $('filterBar');
  bar.replaceChildren();
  const mk = (key, label) => {
    const b = el('button', { cls: 'btn' + (currentTarget === key ? ' active' : ''), text: label });
    b.addEventListener('click', () => { currentTarget = key; loadAll(); });
    bar.appendChild(b);
  };
  mk('', '🇷🇺 Все живые (' + (st.alive_count || 0) + ')');
  for (const t of targetsMeta) {
    const cnt = (st.by_target && st.by_target[t.key]) || 0;
    mk(t.key, t.icon + ' ' + t.name + ' (' + cnt + ')');
  }
}

function uptimeClass(u) {
  if (u >= 80) return 'uptime-good';
  if (u >= 50) return 'uptime-mid';
  return 'uptime-bad';
}

function renderTable(list) {
  const tbody = $('proxyTable');
  tbody.replaceChildren();
  if (!list || list.length === 0) {
    tbody.appendChild(el('tr', null, [el('td', { colspan: 7, cls: 'empty', text: 'Пока нет доступных серверов по выбранному фильтру. Подождите завершения сканирования...' })]));
    return;
  }
  const nameMap = {};
  for (const t of targetsMeta) nameMap[t.key] = t.icon + ' ' + t.name;
  const gov = new Set(['mosgorsud', 'gosuslugi', 'nalog', 'cbr']);

  for (const item of list) {
    const tags = Object.entries(item.targets || {}).map(([k, lat]) =>
      el('span', { cls: gov.has(k) ? 'tag tag-gov' : 'tag', text: (nameMap[k] || k) + ': ' + lat + 'ms' }));

    const geo = el('td', null, [el('div', { cls: 'city', text: '🇷🇺 ' + (item.city || 'Россия') })]);
    if (item.isp) geo.appendChild(el('div', { cls: 'isp', text: item.isp }));
    if (item.exit_ip && item.exit_ip !== String(item.address).split(':')[0]) {
      geo.appendChild(el('div', { cls: 'isp', text: 'выход: ' + item.exit_ip }));
    }

    const copyBtn = el('button', { cls: 'btn', text: 'Копировать' });
    copyBtn.addEventListener('click', () => navigator.clipboard.writeText(String(item.address)));

    const up = Number(item.uptime_percent || 0);
    tbody.appendChild(el('tr', null, [
      el('td', { cls: 'mono', text: item.address }),
      geo,
      el('td', null, [el('span', { cls: 'tag', text: String(item.protocol).toUpperCase() })]),
      el('td', { text: item.avg_latency_ms + ' ms' }),
      el('td', { cls: uptimeClass(up), text: up + '% (' + (item.total_success || 0) + '/' + (item.total_checks || 0) + ')' }),
      el('td', null, tags),
      el('td', null, [copyBtn]),
    ]));
  }
}

function setMsg(id, text, isError) {
  const m = $(id);
  m.textContent = text;
  m.className = 'msg' + (isError ? ' error' : '');
}

async function adminFetch(path, body) {
  const token = $('adminToken').value.trim();
  saveToken(token);
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + token },
    body: body,
  });
  let data = {};
  try { data = await res.json(); } catch (e) { /* пустой ответ */ }
  if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
  return data;
}

document.addEventListener('DOMContentLoaded', () => {
  $('adminToken').value = getToken();

  $('btnCopy').addEventListener('click', () => {
    navigator.clipboard.writeText(currentProxies.map((p) => p.address).join('\n'));
    alert('Скопировано адресов: ' + currentProxies.length);
  });

  $('btnScan').addEventListener('click', async () => {
    try {
      const d = await adminFetch('/api/scan');
      setMsg('scanMsg', d.triggered ? 'Сканирование запущено' : 'Сканирование уже идёт', false);
      loadAll();
    } catch (e) { setMsg('scanMsg', 'Ошибка: ' + e.message, true); }
  });

  $('btnUpload').addEventListener('click', async () => {
    const val = $('customInput').value;
    if (!val.trim()) return;
    try {
      const d = await adminFetch('/api/proxies/add', val);
      setMsg('uploadMsg', 'Принято: ' + d.added + (d.checking_now ? ' (проверяются)' : ' (проверятся в ближайший скан)'), false);
      $('customInput').value = '';
      setTimeout(loadAll, 1500);
    } catch (e) { setMsg('uploadMsg', 'Ошибка: ' + e.message, true); }
  });

  loadAll();
  setInterval(loadAll, 5000);
});
