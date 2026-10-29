package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	workers := 250
	if wStr := os.Getenv("SCAN_WORKERS"); wStr != "" {
		if w, err := strconv.Atoi(wStr); err == nil && w > 0 {
			workers = w
		}
	}

	maxCandidates := 25000 // Сканирует 25 000 уникальных адресов из 23 источников (0 = без лимита)
	if mStr := os.Getenv("MAX_CANDIDATES"); mStr != "" {
		if m, err := strconv.Atoi(mStr); err == nil && m >= 0 {
			maxCandidates = m
		}
	}

	pool := NewProxyPool(workers, maxCandidates)

	// Добавляем стартовый список известных российских узлов для мгновенного старта
	pool.AddCustomCandidates(`
31.40.248.2:8080
`)

	// Запускаем фоновый цикл сканирования каждые 10 минут
	pool.StartBackgroundLoop(10 * time.Minute)

	mux := http.NewServeMux()

	// Healthcheck для Render.com
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Сводная статистика сканера
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(pool.GetStats())
	})

	// Список проверенных прокси с фильтрацией по ресурсу (?target=mosgorsud&protocol=http&format=txt&limit=100)
	mux.HandleFunc("/api/proxies", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w)
		q := r.URL.Query()
		target := strings.TrimSpace(q.Get("target"))
		proto := strings.TrimSpace(q.Get("protocol"))
		format := strings.TrimSpace(q.Get("format"))
		limit, _ := strconv.Atoi(q.Get("limit"))

		items := pool.GetProxies(target, proto, limit)

		if format == "txt" || format == "text" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			for _, item := range items {
				_, _ = fmt.Fprintln(w, item.Address)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   len(items),
			"target":  target,
			"proxies": items,
		})
	})

	// Случайный быстрый рабочий прокси (?target=mosgorsud&format=txt)
	mux.HandleFunc("/api/random", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w)
		q := r.URL.Query()
		target := strings.TrimSpace(q.Get("target"))
		proto := strings.TrimSpace(q.Get("protocol"))
		format := strings.TrimSpace(q.Get("format"))

		chosen, ok := pool.GetRandomProxy(target, proto)
		if !ok {
			http.Error(w, `{"error":"no active proxy found for criteria"}`, http.StatusNotFound)
			return
		}

		if format == "txt" || format == "text" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = fmt.Fprint(w, chosen.Address)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(chosen)
	})

	// Запуск внеочередного сканирования
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w)
		started := pool.TriggerAsyncScan()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"triggered": started,
			"message":   "Scan cycle triggered",
		})
	})

	// Ручное добавление списка адресов на проверку
	mux.HandleFunc("/api/proxies/add", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		added := pool.AddCustomCandidates(string(body))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"added": added,
		})
	})

	// Веб-интерфейс дашборда
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})

	log.Printf("🚀 RuProxyPool запущен на порту :%s (воркеров: %d, лимит пула: %d)", port, workers, maxCandidates)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Ошибка HTTP-сервера: %v", err)
	}
}

func enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RuProxyPool — Сканер доступных серверов для ресурсов РФ</title>
<style>
  :root {
    --bg: #0b0f19;
    --card: #131b2e;
    --border: #1e293b;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --accent: #3b82f6;
    --green: #10b981;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 24px;
    line-height: 1.5;
  }
  .container { max-width: 1200px; margin: 0 auto; }
  header {
    display: flex; justify-content: space-between; align-items: center;
    flex-wrap: wrap; gap: 16px; margin-bottom: 24px;
    padding-bottom: 16px; border-bottom: 1px solid var(--border);
  }
  h1 { font-size: 24px; font-weight: 700; display: flex; align-items: center; gap: 10px; }
  .badge-live {
    font-size: 12px; padding: 4px 10px; border-radius: 999px;
    background: rgba(16, 185, 129, 0.15); color: var(--green); font-weight: 600;
  }
  .stats-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px; margin-bottom: 20px;
  }
  .stat-card {
    background: var(--card); border: 1px solid var(--border);
    padding: 16px 20px; border-radius: 12px;
  }
  .stat-label { font-size: 13px; color: var(--muted); }
  .stat-val { font-size: 28px; font-weight: 700; margin-top: 4px; }
  .progress-wrap {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 10px; padding: 12px 16px; margin-bottom: 20px;
  }
  .progress-bar {
    height: 8px; background: #1e293b; border-radius: 4px; overflow: hidden; margin-top: 8px;
  }
  .progress-fill {
    height: 100%; background: linear-gradient(90deg, #3b82f6, #10b981);
    width: 0%; transition: width 0.4s ease;
  }
  .filters {
    display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 20px;
  }
  .btn {
    background: var(--card); color: var(--text); border: 1px solid var(--border);
    padding: 8px 14px; border-radius: 8px; cursor: pointer; font-size: 13px;
    transition: all 0.15s; display: inline-flex; align-items: center; gap: 6px;
  }
  .btn:hover { border-color: var(--accent); }
  .btn.active { background: var(--accent); border-color: var(--accent); color: #fff; font-weight: 600; }
  .btn-primary { background: var(--accent); border-color: var(--accent); color: #fff; font-weight: 600; }
  .table-card {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; overflow: hidden; margin-bottom: 24px;
  }
  table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }
  th, td { padding: 12px 16px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; }
  .tag {
    display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 12px;
    margin: 2px; background: rgba(59, 130, 246, 0.15); color: #93c5fd;
  }
  .tag-gov { background: rgba(16, 185, 129, 0.15); color: #6ee7b7; }
  .code-box {
    background: #0f172a; border: 1px solid var(--border); border-radius: 8px;
    padding: 12px; font-family: monospace; font-size: 13px; color: #93c5fd; margin-top: 8px;
  }
  textarea {
    width: 100%; height: 90px; background: #0f172a; color: var(--text);
    border: 1px solid var(--border); border-radius: 8px; padding: 10px;
    font-family: monospace; margin: 8px 0;
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>🛡️ RuProxyPool <span id="scanBadge" class="badge-live">Активен</span></h1>
      <div style="color: var(--muted); font-size: 14px; margin-top: 4px;">
        Проверка сайтов РФ и фактического российского выхода прокси. Работа VPN и доступность в мобильной сети проверяются отдельно.
      </div>
    </div>
    <div style="display: flex; gap: 10px;">
      <button class="btn" onclick="copyAllProxies()">📋 Скопировать список (TXT)</button>
      <button class="btn btn-primary" onclick="triggerScan()">🔄 Запустить пересканирование</button>
    </div>
  </header>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Проанализировано (31 база)</div>
      <div class="stat-val" id="stRaw">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Отсеяно иностранных (не РФ)</div>
      <div class="stat-val" style="color: #f87171;" id="stForeign">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Отобрано серверов РФ (RU)</div>
      <div class="stat-val" style="color: #fbbf24;" id="stTotal">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Проверено RU-серверов</div>
      <div class="stat-val" id="stScanned">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Живых серверов РФ 🇷🇺</div>
      <div class="stat-val" style="color: var(--green);" id="stAlive">0</div>
    </div>
  </div>

  <div class="progress-wrap">
    <div style="display:flex; justify-content:space-between; font-size:13px;">
      <span id="progressText">Подготовка к сканированию...</span>
      <span id="progressPercent">0%</span>
    </div>
    <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
  </div>

  <div class="filters" id="filterBar"></div>

  <div class="table-card">
    <table>
      <thead>
        <tr>
          <th>Адрес (IP:Port)</th>
          <th>📍 Выход / Город / Провайдер</th>
          <th>Протокол</th>
          <th>Средний отклик</th>
          <th>Доступные ресурсы РФ (Пинг)</th>
          <th>Действие</th>
        </tr>
      </thead>
      <tbody id="proxyTable">
        <tr><td colspan="6" style="text-align:center; color:var(--muted); padding:32px;">Идет сканирование российских адресов, первые живые серверы появятся через несколько секунд...</td></tr>
      </tbody>
    </table>
  </div>

  <div class="stat-card" style="margin-bottom: 20px;">
    <h3 style="font-size: 16px; margin-bottom: 8px;">🔌 Примеры подключения по API (для парсера Мосгорсуда и других скриптов)</h3>
    <div class="code-box">
      GET /api/random?target=mosgorsud&amp;format=txt  ➔ Возвращает 1 быстрый рабочий IP:Port текстом<br>
      GET /api/proxies?target=mosgorsud&amp;format=txt ➔ Возвращает список всех рабочих IP:Port для Мосгорсуда<br>
      GET /api/proxies?target=gosuslugi            ➔ JSON-список серверов РФ с городами и пингами для Госуслуг
    </div>
  </div>

  <div class="stat-card">
    <h3 style="font-size: 16px;">➕ Добавить свои адреса на проверку</h3>
    <textarea id="customInput" placeholder="Вставьте список IP:Port (каждый с новой строки)..."></textarea>
    <button class="btn btn-primary" onclick="uploadCustom()">Проверить и добавить в пул</button>
    <span id="uploadMsg" style="margin-left: 12px; font-size: 13px; color: var(--green);"></span>
  </div>
</div>

<script>
let currentTarget = "";
let currentProxies = [];
let targetsMeta = [];

async function loadAll() {
  try {
    const stRes = await fetch('/api/stats');
    const st = await stRes.json();
    targetsMeta = st.targets_meta || [];

    document.getElementById('stRaw').textContent = (st.raw_analyzed || 0).toLocaleString('ru-RU');
    document.getElementById('stForeign').textContent = (st.foreign_filtered || 0).toLocaleString('ru-RU');
    document.getElementById('stTotal').textContent = (st.total_candidates || 0).toLocaleString('ru-RU');
    document.getElementById('stScanned').textContent = (st.scanned_count || 0).toLocaleString('ru-RU');
    document.getElementById('stAlive').textContent = st.alive_count;

    const pct = st.total_candidates > 0 ? Math.min(100, Math.round((st.scanned_count / st.total_candidates) * 100)) : 0;
    document.getElementById('progressFill').style.width = pct + '%';
    document.getElementById('progressPercent').textContent = pct + '%';
    document.getElementById('progressText').textContent = st.scan_in_progress
      ? '🔍 Идет многопоточное сканирование серверов РФ (' + st.scanned_count + ' из ' + st.total_candidates + ')...'
      : '✅ Сканирование завершено. Авто-обновление активно.';

    renderFilters(st);

    const url = currentTarget ? '/api/proxies?target=' + encodeURIComponent(currentTarget) : '/api/proxies';
    const prRes = await fetch(url);
    const prData = await prRes.json();
    currentProxies = prData.proxies || [];
    renderTable(currentProxies);
  } catch (e) {
    console.error(e);
  }
}

function renderFilters(st) {
  const bar = document.getElementById('filterBar');
  let html = '<button class="btn ' + (currentTarget === '' ? 'active' : '') + '" onclick="setTarget(\'\')">🇷🇺 Все живые РФ (' + st.alive_count + ')</button>';
  for (const t of targetsMeta) {
    const cnt = (st.by_target && st.by_target[t.key]) || 0;
    const active = currentTarget === t.key ? 'active' : '';
    html += '<button class="btn ' + active + '" onclick="setTarget(\'' + t.key + '\')">' + t.icon + ' ' + t.name + ' (' + cnt + ')</button>';
  }
  bar.innerHTML = html;
}

function renderTable(list) {
  const tbody = document.getElementById('proxyTable');
  if (!list || list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--muted); padding:28px;">Пока нет доступных серверов по выбранному фильтру. Подождите завершения сканирования...</td></tr>';
    return;
  }
  const nameMap = {};
  for (const t of targetsMeta) nameMap[t.key] = t.icon + ' ' + t.name;

  tbody.innerHTML = list.map(item => {
    const tags = Object.entries(item.targets || {}).map(([k, lat]) => {
      const cls = (k === 'mosgorsud' || k === 'gosuslugi' || k === 'nalog' || k === 'cbr') ? 'tag tag-gov' : 'tag';
      return '<span class="' + cls + '">' + (nameMap[k] || k) + ': ' + lat + 'ms</span>';
    }).join('');
    const cityStr = escapeHTML(item.city || item.region || 'RU по геобазе');
    const ispStr = item.isp ? '<div style="font-size:11px; color:var(--muted);">' + escapeHTML(item.isp) + '</div>' : '';
    const checked = item.exit_checked_at ? new Date(item.exit_checked_at).toLocaleString() : '';
    const exitStr = item.exit_verified ? '<div style="font-size:11px; color:var(--muted);" title="' + escapeHTML(checked) + '">Выход: ' + escapeHTML(item.exit_ip) + '</div>' : '';
    return '<tr>' +
      '<td style="font-family:monospace; font-weight:600;">' + item.address + '</td>' +
      '<td><div style="font-weight:600;">🇷🇺 ' + cityStr + '</div>' + exitStr + ispStr + '</td>' +
      '<td><span class="tag">' + item.protocol.toUpperCase() + '</span></td>' +
      '<td>' + item.avg_latency_ms + ' ms</td>' +
      '<td>' + tags + '</td>' +
      '<td><button class="btn" onclick="navigator.clipboard.writeText(\'' + item.address + '\')">Копировать</button></td>' +
    '</tr>';
  }).join('');
}

function escapeHTML(value) {
  const element = document.createElement('span');
  element.textContent = String(value);
  return element.innerHTML.replace(/"/g, '&quot;');
}

function setTarget(t) {
  currentTarget = t;
  loadAll();
}

function copyAllProxies() {
  const txt = currentProxies.map(p => p.address).join('\n');
  navigator.clipboard.writeText(txt);
  alert('Скопировано адресов: ' + currentProxies.length);
}

async function triggerScan() {
  await fetch('/api/scan', { method: 'POST' });
  loadAll();
}

async function uploadCustom() {
  const val = document.getElementById('customInput').value;
  if (!val.trim()) return;
  const res = await fetch('/api/proxies/add', { method: 'POST', body: val });
  const data = await res.json();
  document.getElementById('uploadMsg').textContent = 'Отправлено на проверку: ' + data.added;
  document.getElementById('customInput').value = '';
  setTimeout(loadAll, 1500);
}

loadAll();
setInterval(loadAll, 3000);
</script>
</body>
</html>
`
