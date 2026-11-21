package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config собирает все настройки сервиса из переменных окружения
type Config struct {
	Port            string
	Workers         int
	MaxCandidates   int
	AdminToken      string        // ADMIN_TOKEN: без него служебные эндпоинты отключены
	DataFile        string        // DATA_FILE: куда сохранять пул между перезапусками ("" = не сохранять)
	CertsDir        string        // CERTS_DIR: дополнительные корневые сертификаты (.pem/.crt)
	FullScanEvery   time.Duration // FULL_SCAN_INTERVAL: полный сбор из источников
	RecheckEvery    time.Duration // RECHECK_INTERVAL: перепроверка живых прокси
	MaxFails        int           // MAX_FAILS: после стольких провалов подряд прокси удаляется
	TrustProxyHdr   bool          // TRUST_PROXY: доверять X-Forwarded-For (на Render включается сам)
	PublicRPM       int           // RATE_LIMIT_RPM: запросов в минуту с одного IP к публичному API
	AdminRPM        int           // ADMIN_RATE_LIMIT_RPM: запросов в минуту к служебным эндпоинтам
	MaxCustomList   int           // MAX_CUSTOM: максимум пользовательских адресов в памяти
	MaxAddPerCall   int           // MAX_ADD_PER_CALL: максимум адресов в одном запросе /api/proxies/add
	CheckIPURL      string        // CHECK_IP_URL: сервис, возвращающий IP клиента простым текстом
	ShutdownTimeout time.Duration
}

func LoadConfig() Config {
	cfg := Config{
		Port:            envStr("PORT", "8080"),
		Workers:         envInt("SCAN_WORKERS", 250, 1),
		MaxCandidates:   envInt("MAX_CANDIDATES", 25000, 0),
		AdminToken:      strings.TrimSpace(os.Getenv("ADMIN_TOKEN")),
		DataFile:        envStr("DATA_FILE", "data/pool.json"),
		CertsDir:        envStr("CERTS_DIR", "certs"),
		FullScanEvery:   envDur("FULL_SCAN_INTERVAL", 10*time.Minute),
		RecheckEvery:    envDur("RECHECK_INTERVAL", 2*time.Minute),
		MaxFails:        envInt("MAX_FAILS", 3, 1),
		TrustProxyHdr:   envBool("TRUST_PROXY", os.Getenv("RENDER") != ""),
		PublicRPM:       envInt("RATE_LIMIT_RPM", 300, 1),
		AdminRPM:        envInt("ADMIN_RATE_LIMIT_RPM", 10, 1),
		MaxCustomList:   envInt("MAX_CUSTOM", 5000, 1),
		MaxAddPerCall:   envInt("MAX_ADD_PER_CALL", 1000, 1),
		CheckIPURL:      envStr("CHECK_IP_URL", "https://api.ipify.org"),
		ShutdownTimeout: 15 * time.Second,
	}
	if os.Getenv("DATA_FILE") == "-" {
		cfg.DataFile = ""
	}

	switch {
	case cfg.AdminToken == "":
		log.Printf("⚠️  ADMIN_TOKEN не задан: /api/scan и /api/proxies/add отключены")
	case len(cfg.AdminToken) < 24:
		log.Printf("⚠️  ADMIN_TOKEN короче 24 символов — используйте длинный случайный токен (openssl rand -hex 32)")
	}
	return cfg
}

func envStr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func envInt(name string, def, min int) int {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= min {
			return n
		}
		log.Printf("⚠️  %s=%q некорректно, используется %d", name, v, def)
	}
	return def
}

func envDur(name string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 10*time.Second {
			return d
		}
		log.Printf("⚠️  %s=%q некорректно (пример: 2m, 10m), используется %v", name, v, def)
	}
	return def
}

func envBool(name string, def bool) bool {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
