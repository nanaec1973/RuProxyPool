package main

import "time"

// TargetResource описывает целевой российский ресурс для проверки доступности через прокси
type TargetResource struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Icon     string `json:"icon"`
	Priority bool   `json:"priority"`
}

// TargetList содержит основные российские государственные и инфраструктурные сайты
var TargetList = []TargetResource{
	{
		Key:      "mosgorsud",
		Name:     "Мосгорсуд",
		URL:      "https://mos-gorsud.ru",
		Icon:     "⚖️",
		Priority: true,
	},
	{
		Key:      "gosuslugi",
		Name:     "Госуслуги",
		URL:      "https://www.gosuslugi.ru",
		Icon:     "🏛",
		Priority: true,
	},
	{
		Key:      "cbr",
		Name:     "ЦБ РФ",
		URL:      "https://www.cbr.ru",
		Icon:     "🏦",
		Priority: true,
	},
	{
		Key:      "sber",
		Name:     "Сбербанк",
		URL:      "https://www.sberbank.ru",
		Icon:     "🟢",
		Priority: false,
	},
	{
		Key:      "nalog",
		Name:     "ФНС (Nalog.ru)",
		URL:      "https://www.nalog.gov.ru",
		Icon:     "📋",
		Priority: true,
	},
	{
		Key:      "mos",
		Name:     "Мос.ру",
		URL:      "https://www.mos.ru",
		Icon:     "🏙",
		Priority: true,
	},
	{
		Key:      "rzd",
		Name:     "РЖД",
		URL:      "https://www.rzd.ru",
		Icon:     "🚆",
		Priority: false,
	},
	{
		Key:      "ya",
		Name:     "Яндекс",
		URL:      "https://ya.ru",
		Icon:     "🔎",
		Priority: true,
	},
}

// CandidateProxy описывает сырой адрес прокси для сканирования
type CandidateProxy struct {
	Address  string // IP:Port
	Protocol string // "http" или "socks5"
	Country  string // "RU"
	Source   string // Источник
}

// ProxyResult описывает проверенный рабочий сервер РФ и его доступность к ресурсам РФ
type ProxyResult struct {
	Address       string           `json:"address"`        // IP:Port
	Protocol      string           `json:"protocol"`       // "http" или "socks5"
	Country       string           `json:"country"`        // "RU"
	City          string           `json:"city"`           // Город РФ (например, "Москва", "Новосибирск")
	Region        string           `json:"region"`         // Область / Регион РФ
	ISP           string           `json:"isp"`            // Провайдер / Хостинг
	Source        string           `json:"source"`         // Откуда получен
	TCPPingMs     int64            `json:"tcp_ping_ms"`    // Быстрый TCP пинг в мс
	AvgLatencyMs  int64            `json:"avg_latency_ms"` // Среднее время HTTP-ответа
	Targets       map[string]int64 `json:"targets"`        // Успешные цели: ключ -> пинг в мс
	TargetCount   int              `json:"target_count"`   // Сколько ресурсов РФ открылось
	DirectAccess  bool             `json:"direct_access"`  // Подходит для госресурсов
	LastCheckedAt time.Time        `json:"last_checked_at"`
}
