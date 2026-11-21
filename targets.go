package main

import "time"

// TargetResource описывает целевой российский ресурс для проверки доступности через прокси
type TargetResource struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Icon     string `json:"icon"`
	Priority bool   `json:"priority"`
	// Markers — характерные фрагменты страницы (в нижнем регистре). Ответ засчитывается,
	// только если в нём есть хотя бы один маркер: так отсекаются заглушки, капчи и
	// подменённые страницы, которые формально отвечают кодом 200.
	Markers []string `json:"-"`
}

// TargetList содержит основные российские государственные и инфраструктурные сайты
var TargetList = []TargetResource{
	{
		Key:      "mosgorsud",
		Name:     "Мосгорсуд",
		URL:      "https://mos-gorsud.ru",
		Icon:     "⚖️",
		Priority: true,
		Markers:  []string{"mos-gorsud", "суд"},
	},
	{
		Key:      "gosuslugi",
		Name:     "Госуслуги",
		URL:      "https://www.gosuslugi.ru",
		Icon:     "🏛",
		Priority: true,
		Markers:  []string{"gosuslugi", "госуслуг"},
	},
	{
		Key:      "cbr",
		Name:     "ЦБ РФ",
		URL:      "https://www.cbr.ru",
		Icon:     "🏦",
		Priority: true,
		Markers:  []string{"cbr.ru", "банк россии"},
	},
	{
		Key:      "sber",
		Name:     "Сбербанк",
		URL:      "https://www.sberbank.ru",
		Icon:     "🟢",
		Priority: false,
		Markers:  []string{"sberbank", "сбер"},
	},
	{
		Key:      "nalog",
		Name:     "ФНС (Nalog.ru)",
		URL:      "https://www.nalog.gov.ru",
		Icon:     "📋",
		Priority: true,
		Markers:  []string{"nalog.gov.ru", "nalog.ru", "налог"},
	},
	{
		Key:      "mos",
		Name:     "Мос.ру",
		URL:      "https://www.mos.ru",
		Icon:     "🏙",
		Priority: true,
		Markers:  []string{"mos.ru", "москв"},
	},
	{
		Key:      "rzd",
		Name:     "РЖД",
		URL:      "https://www.rzd.ru",
		Icon:     "🚆",
		Priority: false,
		Markers:  []string{"rzd.ru", "ржд"},
	},
	{
		Key:      "ya",
		Name:     "Яндекс",
		URL:      "https://ya.ru",
		Icon:     "🔎",
		Priority: true,
		Markers:  []string{"yandex", "яндекс", "ya.ru"},
	},
}

// targetByKey возвращает описание цели по ключу
func targetByKey(key string) (TargetResource, bool) {
	for _, t := range TargetList {
		if t.Key == key {
			return t, true
		}
	}
	return TargetResource{}, false
}

// CandidateProxy описывает сырой адрес прокси для сканирования
type CandidateProxy struct {
	Address  string // IP:Port
	Protocol string // "http", "socks5" или "auto" (неизвестен — проверяем оба)
	Country  string // "RU"
	Source   string // Источник
}

// ProxyResult описывает проверенный рабочий сервер РФ и его доступность к ресурсам РФ
type ProxyResult struct {
	Address       string           `json:"address"`         // IP:Port
	Protocol      string           `json:"protocol"`        // "http" или "socks5"
	Country       string           `json:"country"`         // "RU"
	City          string           `json:"city"`            // Город РФ (заполняется в фоне)
	Region        string           `json:"region"`          // Область / Регион РФ
	ISP           string           `json:"isp"`             // Провайдер / Хостинг
	ExitIP        string           `json:"exit_ip"`         // IP, с которого прокси реально выходит в интернет
	Source        string           `json:"source"`          // Откуда получен
	TCPPingMs     int64            `json:"tcp_ping_ms"`     // Быстрый TCP пинг в мс
	AvgLatencyMs  int64            `json:"avg_latency_ms"`  // Среднее время HTTPS-ответа
	Targets       map[string]int64 `json:"targets"`         // Успешные цели: ключ -> пинг в мс
	TargetCount   int              `json:"target_count"`    // Сколько ресурсов РФ открылось
	DirectAccess  bool             `json:"direct_access"`   // Открывает госресурсы
	LastCheckedAt time.Time        `json:"last_checked_at"` // Время последней проверки
	FirstSeenAt   time.Time        `json:"first_seen_at"`   // Когда впервые попал в пул

	// Статистика стабильности
	TotalChecks      int     `json:"total_checks"`
	TotalSuccess     int     `json:"total_success"`
	ConsecutiveFails int     `json:"consecutive_fails"`
	UptimePercent    float64 `json:"uptime_percent"`
}

func (r *ProxyResult) key() string { return r.Protocol + "://" + r.Address }

func (r *ProxyResult) recomputeUptime() {
	if r.TotalChecks <= 0 {
		r.UptimePercent = 0
		return
	}
	r.UptimePercent = float64(int(float64(r.TotalSuccess)*1000/float64(r.TotalChecks))) / 10
}
