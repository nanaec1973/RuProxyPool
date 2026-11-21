package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed static
var staticFiles embed.FS

func main() {
	cfg := LoadConfig()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	checker := NewChecker(cfg.CertsDir, cfg.CheckIPURL)
	pool := NewProxyPool(cfg, checker, newGeoResolver())
	pool.Load()
	pool.Start(ctx)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           withSecurityHeaders(newRouter(cfg, pool)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	go func() {
		log.Printf("🚀 RuProxyPool запущен на порту :%s (воркеров: %d, лимит кандидатов: %d, служебный API: %v)",
			cfg.Port, cfg.Workers, cfg.MaxCandidates, cfg.AdminToken != "")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Ошибка HTTP-сервера: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("Получен сигнал остановки, сохраняю пул и завершаю работу...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	pool.SaveIfDirty()
}

func newRouter(cfg Config, pool *ProxyPool) http.Handler {
	publicRL := newRateLimiter(cfg.PublicRPM)
	adminRL := newRateLimiter(cfg.AdminRPM)
	pub := func(h http.HandlerFunc) http.HandlerFunc {
		return publicCORS(withRateLimit(publicRL, cfg.TrustProxyHdr, h))
	}
	admin := func(h http.HandlerFunc) http.HandlerFunc {
		// Сначала лимит, потом токен: перебор токена упирается в ограничение частоты
		return withRateLimit(adminRL, cfg.TrustProxyHdr, withAdmin(cfg.AdminToken, h))
	}

	mux := http.NewServeMux()

	// Healthcheck для Render.com (без лимита — его дёргает сама платформа)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET /api/stats", pub(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, pool.GetStats())
	}))

	// Список проверенных прокси (?target=mosgorsud&protocol=http&format=txt&limit=100)
	mux.HandleFunc("GET /api/proxies", pub(func(w http.ResponseWriter, r *http.Request) {
		target, proto, format, ok := parseFilters(w, r)
		if !ok {
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit < 0 {
			limit = 0
		}
		items := pool.GetProxies(target, proto, limit)

		if format == "txt" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			for _, item := range items {
				_, _ = fmt.Fprintln(w, item.Address)
			}
			return
		}
		writeJSON(w, map[string]interface{}{"count": len(items), "target": target, "proxies": items})
	}))

	// Случайный быстрый рабочий прокси (?target=mosgorsud&format=txt)
	mux.HandleFunc("GET /api/random", pub(func(w http.ResponseWriter, r *http.Request) {
		target, proto, format, ok := parseFilters(w, r)
		if !ok {
			return
		}
		chosen, found := pool.GetRandomProxy(target, proto)
		if !found {
			writeJSONError(w, http.StatusNotFound, "no active proxy found for criteria")
			return
		}
		if format == "txt" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = fmt.Fprint(w, chosen.Address)
			return
		}
		writeJSON(w, chosen)
	}))

	// Жалоба парсера на нерабочий прокси (?address=IP:Port&protocol=socks5).
	// Прокси не удаляется сразу, а внеочередно перепроверяется.
	mux.HandleFunc("POST /api/report", pub(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		addr := strings.TrimSpace(q.Get("address"))
		proto := strings.TrimSpace(q.Get("protocol"))
		if !isAllowedProxyAddr(addr) || (proto != "" && proto != "http" && proto != "socks5") {
			writeJSONError(w, http.StatusBadRequest, "invalid address or protocol")
			return
		}
		if !pool.Report(addr, proto) {
			writeJSONError(w, http.StatusNotFound, "proxy not in pool")
			return
		}
		writeJSON(w, map[string]interface{}{"accepted": true, "message": "proxy will be rechecked"})
	}))

	// Служебное: внеочередное сканирование
	mux.HandleFunc("POST /api/scan", admin(func(w http.ResponseWriter, r *http.Request) {
		started := pool.TriggerAsyncScan()
		writeJSON(w, map[string]interface{}{"triggered": started})
	}))

	// Служебное: добавить свои адреса на проверку
	mux.HandleFunc("POST /api/proxies/add", admin(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
		if err != nil {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "body too large (max 256 KB)")
			return
		}
		added, now := pool.AddCustomCandidates(string(body))
		writeJSON(w, map[string]interface{}{"added": added, "checking_now": now})
	}))

	// Веб-интерфейс
	sub, _ := fs.Sub(staticFiles, "static")
	fileServer := http.FileServer(http.FS(sub))
	mux.Handle("GET /static/", http.StripPrefix("/static/", fileServer))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFiles.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "dashboard missing", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})

	return mux
}

// parseFilters проверяет общие параметры target / protocol / format
func parseFilters(w http.ResponseWriter, r *http.Request) (target, proto, format string, ok bool) {
	q := r.URL.Query()
	target = strings.TrimSpace(q.Get("target"))
	proto = strings.TrimSpace(q.Get("protocol"))
	format = strings.TrimSpace(q.Get("format"))
	if format == "text" {
		format = "txt"
	}
	if target != "" {
		if _, known := targetByKey(target); !known {
			writeJSONError(w, http.StatusBadRequest, "unknown target")
			return "", "", "", false
		}
	}
	if proto != "" && proto != "http" && proto != "socks5" {
		writeJSONError(w, http.StatusBadRequest, "protocol must be http or socks5")
		return "", "", "", false
	}
	if format != "" && format != "txt" && format != "json" {
		writeJSONError(w, http.StatusBadRequest, "format must be json or txt")
		return "", "", "", false
	}
	return target, proto, format, true
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
