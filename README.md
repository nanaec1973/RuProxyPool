# 🛡️ RuProxyPool — Автоматический сканер и API доступных серверов для ресурсов РФ

Высокоскоростной сервис на **Go** (без внешних зависимостей), который в фоновом режиме собирает тысячи кандидатов прокси-серверов (`HTTP` и `SOCKS5`), параллельно проверяет их пробиваемость к ключевым государственным и инфраструктурным ресурсам РФ и отдает готовые рабочие адреса через **REST API** и **интерактивный веб-дашборд**.

🌐 **Боевой сервер (Live Dashboard & API):**  
👉 **[https://ru-proxy-pool.onrender.com](https://ru-proxy-pool.onrender.com)**

---

## 🎯 Проверяемые целевые ресурсы (`target`)

Каждый найденный сервер проверяется на реальное прохождение TLS/HTTPS-соединения и получение ответа `2xx/3xx` (без гео-блокировки `403 Forbidden`):

| Код (`target`) | Ресурс | URL проверки | Назначение |
|---|---|---|---|
| `mosgorsud` | ⚖️ **Мосгорсуд** | `https://mos-gorsud.ru` | Парсинг судебных дел и картотеки судов |
| `gosuslugi` | 🏛 **Госуслуги** | `https://www.gosuslugi.ru` | Доступ к порталу государственных услуг |
| `cbr` | 🏦 **ЦБ РФ** | `https://www.cbr.ru` | Курсы валют, API и реестры Банка России |
| `nalog` | 📋 **ФНС России** | `https://www.nalog.gov.ru` | Проверка контрагентов (ЕГРЮЛ/ЕГРИП), сервисы ФНС |
| `mos` | 🏙 **Мос.ру** | `https://www.mos.ru` | Городские сервисы Москвы |
| `sber` | 🟢 **Сбербанк** | `https://www.sberbank.ru` | Проверка прохождения трафика с российским сертификатом |
| `rzd` | 🚆 **РЖД** | `https://www.rzd.ru` | Проверка доступности билетных и транспортных шлюзов |
| `ya` | 🔎 **Яндекс** | `https://ya.ru` | Базовый маркер прохождения трафика в Рунет |

---

## 🏗 Архитектура проекта

```text
RuProxyPool/
├── main.go       # HTTP-сервер, REST API эндпоинты и встроенный живой Web-дашборд
├── targets.go    # Описание целевых ресурсов РФ и структур данных (ProxyResult)
├── fetcher.go    # Агрегатор тысяч адресов из публичных RU и глобальных фидов
├── checker.go    # Двухэтапный валидатор (TCP-пинг + параллельный HTTPS/SOCKS5 тест)
├── pool.go       # Потокобезопасное хранилище живых серверов и планировщик (Worker Pool)
├── Dockerfile    # Многоступенчатая сборка легковесного контейнера (Alpine Linux)
└── go.mod        # Модуль Go (0 внешних зависимостей — только стандартная библиотека)
```

### Как работает цикл сканирования:
1. **Сбор кандидатов (`fetcher.go`):** Параллельно опрашивает специализированные российские (`RU`) и международные источники (`Proxifly-RU`, `ProxyScrape-RU`, `GeoNode-RU`, `Spys.me`, `Monosans`, `TheSpeedX` и др.), собирая до `3000+` уникальных адресов за 1 секунду. Приоритет отдается узлам с геолокацией `RU`.
2. **Этап 1 — Быстрый TCP-фильтр (`checker.go`):** 180 параллельных горутин проверяют TCP-соединение с таймаутом `1.8 сек`, мгновенно отсеивая неактивные IP.
3. **Этап 2 — Проверка HTTPS и SOCKS5 (RFC 1928):** Для живых узлов поднимается туннель (`HTTP CONNECT` или встроенный `SOCKS5`) и параллельно проверяются все 8 российских ресурсов.
4. **Живое обновление (`pool.go`):** Как только воркер находит рабочий сервер, он мгновенно попадает в выдачу API и таблицу дашборда (полный цикл проверки 3000 адресов занимает ~30 секунд). Пересканирование запускается автоматически каждые 10 минут.

---

## 🔌 Документация REST API

### 1. Получить один быстрый рабочий сервер (`/api/random`)
Возвращает случайный сервер из топ-25 самых быстрых для указанного сайта. Идеально для автоматической подстановки в парсеры перед запуском.

**Параметры запроса:**
* `target` *(необязательно)* — фильтр по ресурсу (`mosgorsud`, `gosuslugi`, `cbr`, `nalog`, `mos`, `sber`, `rzd`, `ya`).
* `protocol` *(необязательно)* — `http` или `socks5`.
* `format` *(необязательно)* — `json` (по умолчанию) или `txt` (возвращает только строку `IP:Port` или `protocol://IP:Port`).

**Примеры:**
```bash
# Получить один готовый IP:Port для Мосгорсуда простым текстом
curl -s "https://ru-proxy-pool.onrender.com/api/random?target=mosgorsud&format=txt"
# Ответ: 77.221.148.116:10808

# Получить полную карточку случайного сервера для Мосгорсуда в JSON
curl -s "https://ru-proxy-pool.onrender.com/api/random?target=mosgorsud"
```

---

### 2. Получить список всех проверенных серверов (`/api/proxies`)
Возвращает список всех живых серверов, отсортированный по качеству и минимальному пингу до выбранной цели.

**Параметры запроса:**
* `target` *(необязательно)* — фильтр по ресурсу (например, `mosgorsud`).
* `protocol` *(необязательно)* — `http` или `socks5`.
* `limit` *(необязательно)* — ограничение количества записей (например, `limit=20`).
* `format` *(необязательно)* — `json` или `txt` (список `IP:Port` по одному на строку).

**Примеры:**
```bash
# Скачать текстовый список всех живых серверов для Мосгорсуда
curl -s "https://ru-proxy-pool.onrender.com/api/proxies?target=mosgorsud&format=txt"

# Получить JSON со всеми серверами, открывающими Госуслуги
curl -s "https://ru-proxy-pool.onrender.com/api/proxies?target=gosuslugi"
```

**Пример JSON-ответа:**
```json
{
  "count": 6,
  "target": "mosgorsud",
  "proxies": [
    {
      "address": "185.179.189.248:1080",
      "protocol": "socks5",
      "country": "RU",
      "source": "Proxifly-RU",
      "tcp_ping_ms": 45,
      "avg_latency_ms": 631,
      "targets": {
        "cbr": 363,
        "gosuslugi": 324,
        "mos": 379,
        "mosgorsud": 881,
        "nalog": 678,
        "rzd": 876,
        "ya": 921
      },
      "target_count": 7,
      "direct_access": true,
      "last_checked_at": "2026-10-25T16:22:16Z"
    }
  ]
}
```

---

### 3. Сводная статистика пула (`/api/stats`)
Возвращает текущее состояние сканера, прогресс проверки и количество живых серверов по каждому ресурсу РФ.

```bash
curl -s "https://ru-proxy-pool.onrender.com/api/stats"
```

---

### 4. Запустить внеочередное сканирование (`POST /api/scan`)
Принудительно запускает новый цикл сбора и проверки кандидатов в фоновом режиме.

```bash
curl -X POST "https://ru-proxy-pool.onrender.com/api/scan"
```

---

### 5. Добавить свои адреса на проверку (`POST /api/proxies/add`)
Позволяет отправить свой список `IP:Port` (текстом, по одному на строку, с префиксом `http://` / `socks5://` или без него). Сервис мгновенно проверит их и добавит живые в пул.

```bash
curl -X POST "https://ru-proxy-pool.onrender.com/api/proxies/add" \
  --data-binary $'31.40.248.2:8080\nsocks5://77.221.148.116:10808'
```

---

## 💻 Примеры интеграции в ваши проекты

### Интеграция в Go (например, для парсера Мосгорсуда с Selenium / Chrome)

```go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type ProxyItem struct {
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
}

// GetLiveMosgorsudProxy запрашивает у нашего сервиса самый быстрый живой прокси для Мосгорсуда
func GetLiveMosgorsudProxy() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://ru-proxy-pool.onrender.com/api/random?target=mosgorsud")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var item ProxyItem
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		return "", err
	}
	// Формат для флага Chrome: "--proxy-server=socks5://77.221.148.116:10808" или "http://..."
	return fmt.Sprintf("%s://%s", item.Protocol, item.Address), nil
}

func main() {
	proxyURL, err := GetLiveMosgorsudProxy()
	if err != nil {
		panic(err)
	}
	fmt.Println("Используем проверенный прокси для Мосгорсуда:", proxyURL)
	// Передаем в ChromeOptions: "--proxy-server=" + proxyURL
}
```

### Интеграция в Python (`requests`)

```python
import requests

# Получаем случайный проверенный прокси для Мосгорсуда
r = requests.get("https://ru-proxy-pool.onrender.com/api/random?target=mosgorsud").json()
proxy_url = f"{r['protocol']}://{r['address']}"

print(f"Подключаемся через {proxy_url}...")
resp = requests.get("https://mos-gorsud.ru", proxies={"http": proxy_url, "https": proxy_url}, timeout=10)
print("Статус Мосгорсуда:", resp.status_code)
```

---

## ⚙️ Переменные окружения (Конфигурация)

Сервис работает без какой-либо настройки из коробки, но при необходимости поддерживает переменные окружения:

| Переменная | По умолчанию | Описание |
|---|---|---|
| `PORT` | `8080` | HTTP-порт веб-сервера и API (на Render подставляется автоматически) |
| `SCAN_WORKERS` | `250` | Количество параллельных горутин-воркеров при сканировании |
| `MAX_CANDIDATES` | `25000` | Размер пула кандидатов на цикл (25 000 адресов из 23 источников; `0` = без лимита до ~105 000) |

---

## 🚀 Локальный запуск и Docker

### Запуск напрямую через Go:
```bash
git clone https://github.com/nanaec1973/RuProxyPool.git
cd RuProxyPool
go run .
```
После запуска откройте в браузере `http://localhost:8080`.

### Сборка и запуск в Docker:
```bash
docker build -t ru-proxy-pool .
docker run -d -p 8080:8080 --name ru-proxy-pool ru-proxy-pool
```
