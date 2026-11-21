package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- Фильтр адресов (защита от SSRF / сканирования внутренних сетей) ----------

var blockedPrefixes = func() []netip.Prefix {
	list := []string{
		"0.0.0.0/8",       // "эта" сеть
		"10.0.0.0/8",      // частная
		"100.64.0.0/10",   // CGNAT
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local, в т.ч. метаданные облаков (169.254.169.254)
		"172.16.0.0/12",   // частная
		"192.0.0.0/24",    // IETF
		"192.0.2.0/24",    // документация
		"192.168.0.0/16",  // частная
		"198.18.0.0/15",   // бенчмарки
		"198.51.100.0/24", // документация
		"203.0.113.0/24",  // документация
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // зарезервировано + broadcast
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Порты, на которые не стоит отправлять HTTP/SOCKS-рукопожатия: почта, DNS, SSH и т.п.
// Защищает от того, чтобы сервис использовали для «простукивания» чужих служб.
var blockedPorts = map[int]bool{
	0: true, 22: true, 23: true, 25: true, 53: true, 110: true, 143: true,
	465: true, 587: true, 993: true, 995: true,
}

// isAllowedProxyAddr разрешает только публичные IPv4-адреса с нормальным портом.
func isAllowedProxyAddr(addr string) bool {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || blockedPorts[port] {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// ---------- Ограничение частоты запросов (token bucket на IP клиента) ----------

type rateLimiter struct {
	mu       sync.Mutex
	perMin   float64
	burst    float64
	visitors map[string]*bucket
	lastGC   time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMinute int) *rateLimiter {
	burst := float64(perMinute) / 4
	if burst < 3 {
		burst = 3
	}
	return &rateLimiter{
		perMin:   float64(perMinute),
		burst:    burst,
		visitors: make(map[string]*bucket),
		lastGC:   time.Now(),
	}
}

func (rl *rateLimiter) Allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if now.Sub(rl.lastGC) > 5*time.Minute {
		for k, b := range rl.visitors {
			if now.Sub(b.last) > 10*time.Minute {
				delete(rl.visitors, k)
			}
		}
		rl.lastGC = now
	}

	b, ok := rl.visitors[key]
	if !ok {
		b = &bucket{tokens: rl.burst, last: now}
		rl.visitors[key] = b
	}
	b.tokens += now.Sub(b.last).Minutes() * rl.perMin
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// clientIP определяет IP клиента. X-Forwarded-For учитывается только за доверенным
// балансировщиком (Render), и берётся ПОСЛЕДНИЙ адрес — его добавил сам балансировщик,
// а левые значения клиент может подделать.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func withRateLimit(rl *rateLimiter, trustProxy bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(clientIP(r, trustProxy)) {
			w.Header().Set("Retry-After", "10")
			writeJSONError(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		next(w, r)
	}
}

// ---------- Авторизация служебных эндпоинтов ----------

// withAdmin пропускает запрос, только если передан правильный ADMIN_TOKEN
// (заголовок "Authorization: Bearer <token>" или "X-API-Key: <token>").
// Сравнение — за постоянное время, чтобы токен нельзя было подобрать по времени ответа.
func withAdmin(token string, next http.HandlerFunc) http.HandlerFunc {
	expected := sha256.Sum256([]byte(token))
	return func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			writeJSONError(w, http.StatusForbidden, "admin endpoints are disabled: set ADMIN_TOKEN")
			return
		}
		got := r.Header.Get("X-API-Key")
		if got == "" {
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				got = strings.TrimPrefix(auth, "Bearer ")
			}
		}
		gotHash := sha256.Sum256([]byte(strings.TrimSpace(got)))
		if got == "" || subtle.ConstantTimeCompare(gotHash[:], expected[:]) != 1 {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// ---------- Заголовки безопасности ----------

const dashboardCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
	"img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", dashboardCSP)
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// publicCORS разрешает чтение публичного API с любых сайтов (только GET, без cookies).
// Служебные эндпоинты CORS-заголовков не получают.
func publicCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET")
		next(w, r)
	}
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"error":` + strconv.Quote(msg) + `}`))
}
