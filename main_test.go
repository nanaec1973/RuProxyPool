package main

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsAllowedProxyAddr(t *testing.T) {
	cases := map[string]bool{
		"77.88.55.60:1080":   true,
		"5.255.255.5:8080":   true,
		"127.0.0.1:8080":     false,
		"10.1.2.3:3128":      false,
		"192.168.1.1:1080":   false,
		"172.20.0.5:80":      false,
		"169.254.169.254:80": false, // метаданные облака
		"100.64.1.1:8080":    false,
		"0.0.0.0:80":         false,
		"224.0.0.1:80":       false,
		"255.255.255.255:80": false,
		"77.88.55.60:25":     false, // SMTP
		"77.88.55.60:22":     false, // SSH
		"77.88.55.60:0":      false,
		"77.88.55.60:70000":  false,
		"[2a02:6b8::1]:1080": false, // только IPv4
		"example.com:8080":   false,
		"garbage":            false,
	}
	for addr, want := range cases {
		if got := isAllowedProxyAddr(addr); got != want {
			t.Errorf("isAllowedProxyAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestEvaluateResponse(t *testing.T) {
	cbr, _ := targetByKey("cbr")
	u := func(s string) *url.URL { p, _ := url.Parse(s); return p }
	page := []byte("<html><head><title>Банк России</title></head><body>" + strings.Repeat("x", 300) + "</body></html>")

	if !evaluateResponse(cbr, 200, u("https://www.cbr.ru/"), page) {
		t.Error("нормальная страница должна засчитываться")
	}
	if evaluateResponse(cbr, 403, u("https://www.cbr.ru/"), page) {
		t.Error("403 не должен засчитываться")
	}
	if evaluateResponse(cbr, 200, u("https://www.cbr.ru/"), []byte("<html>ok</html>")) {
		t.Error("слишком короткий ответ не должен засчитываться")
	}
	if evaluateResponse(cbr, 200, u("https://ads.example.com/"), page) {
		t.Error("редирект на чужой домен не должен засчитываться")
	}
	if evaluateResponse(cbr, 200, u("https://www.cbr.ru/showcaptcha?x=1"), page) {
		t.Error("капча не должна засчитываться")
	}
	stub := []byte(strings.Repeat("a", 300) + " Checking your browser before accessing cbr.ru")
	if evaluateResponse(cbr, 200, u("https://www.cbr.ru/"), stub) {
		t.Error("анти-бот заглушка не должна засчитываться")
	}
	foreign := []byte("<html>" + strings.Repeat("lorem ipsum ", 50) + "</html>")
	if evaluateResponse(cbr, 200, u("https://www.cbr.ru/"), foreign) {
		t.Error("страница без маркеров сайта не должна засчитываться")
	}
}

func TestSameSite(t *testing.T) {
	if !sameSite("www.cbr.ru", "cbr.ru") || !sameSite("ya.ru", "sso.ya.ru") {
		t.Error("www и поддомены — тот же сайт")
	}
	if sameSite("cbr.ru", "evilcbr.ru") || sameSite("cbr.ru", "cbr.ru.evil.com") {
		t.Error("похожие домены — другой сайт")
	}
}

func TestParsers(t *testing.T) {
	raw := "socks5://1.2.3.4:1080\nhttp://5.6.7.8:8080\n9.9.9.9:3128\nsocks4://4.4.4.4:1\n# comment\n"
	got := parseRawLines(raw, "auto", "RU", "T")
	if len(got) != 3 || got[0].Protocol != "socks5" || got[1].Protocol != "http" || got[2].Protocol != "auto" {
		t.Fatalf("parseRawLines: %+v", got)
	}

	spys := "1.1.1.1:80 RU-H-S +\n2.2.2.2:80 US-H -\n"
	if s := parseSpysTxt(spys, "http", "S"); len(s) != 1 || s[0].Address != "1.1.1.1:80" {
		t.Fatalf("parseSpysTxt: %+v", s)
	}

	gn := `{"data":[{"ip":"3.3.3.3","port":"1080","protocols":["socks5"],"country":"RU"}]}`
	if g, err := parseGeoNodeJSON(gn, "G"); err != nil || len(g) != 1 || g[0].Protocol != "socks5" {
		t.Fatalf("parseGeoNodeJSON: %+v %v", g, err)
	}

	if e := expandProtocols(CandidateProxy{Address: "1.2.3.4:1", Protocol: "auto"}); len(e) != 2 {
		t.Fatal("auto должен раскрываться в два протокола")
	}
	if e := expandProtocols(CandidateProxy{Address: "1.2.3.4:1", Protocol: "http"}); len(e) != 1 {
		t.Fatal("известный протокол не должен раскрываться")
	}
}

func TestWithAdmin(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }
	do := func(h http.HandlerFunc, hdr, val string) int {
		req := httptest.NewRequest("POST", "/api/scan", nil)
		if hdr != "" {
			req.Header.Set(hdr, val)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec.Code
	}

	if c := do(withAdmin("", ok), "Authorization", "Bearer "); c != 403 {
		t.Errorf("без ADMIN_TOKEN ожидался 403, получен %d", c)
	}
	h := withAdmin("secret-token-1234567890abcdef", ok)
	if c := do(h, "", ""); c != 401 {
		t.Errorf("без токена ожидался 401, получен %d", c)
	}
	if c := do(h, "Authorization", "Bearer wrong"); c != 401 {
		t.Errorf("с неверным токеном ожидался 401, получен %d", c)
	}
	if c := do(h, "Authorization", "Bearer secret-token-1234567890abcdef"); c != 200 {
		t.Errorf("с верным Bearer ожидался 200, получен %d", c)
	}
	if c := do(h, "X-API-Key", "secret-token-1234567890abcdef"); c != 200 {
		t.Errorf("с верным X-API-Key ожидался 200, получен %d", c)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(12) // burst = 3
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow("1.1.1.1") {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("ожидалось 3 разрешённых запроса подряд, получено %d", allowed)
	}
	if !rl.Allow("2.2.2.2") {
		t.Error("лимит должен считаться отдельно для каждого IP")
	}
}

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 7.7.7.7")
	if ip := clientIP(req, false); ip != "10.0.0.1" {
		t.Errorf("без доверия к прокси заголовок должен игнорироваться, получено %s", ip)
	}
	if ip := clientIP(req, true); ip != "7.7.7.7" {
		t.Errorf("за балансировщиком берётся последний адрес, получено %s", ip)
	}
}

// Минимальный SOCKS5-сервер для проверки рукопожатия
func TestDialSOCKS5(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 3)
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Write([]byte{0x05, 0x00})
		hdr := make([]byte, 5)
		_, _ = io.ReadFull(c, hdr) // VER CMD RSV ATYP LEN
		rest := make([]byte, int(hdr[4])+2)
		_, _ = io.ReadFull(c, rest)
		if string(rest[:len(rest)-2]) != "example.org" {
			return
		}
		_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
		_, _ = c.Write([]byte("hello"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialSOCKS5(ctx, ln.Addr().String(), "example.org:443")
	if err != nil {
		t.Fatalf("dialSOCKS5: %v", err)
	}
	defer conn.Close()
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello" {
		t.Fatalf("данные после рукопожатия: %q %v", got, err)
	}
}

// Сертификат, которому мы не доверяем (как у MITM-прокси), должен отвергаться
func TestTLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html>Банк России "+strings.Repeat("x", 300)+"</html>")
	}))
	defer srv.Close()

	target := TargetResource{Key: "test", URL: srv.URL, Markers: []string{"банк россии"}}
	ch := &Checker{roots: x509.NewCertPool()}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: ch.tlsConfig()}}
	if _, ok := testTarget(client, target); ok {
		t.Fatal("недоверенный сертификат не должен проходить проверку")
	}

	trusted := x509.NewCertPool()
	trusted.AddCert(srv.Certificate())
	ch.roots = trusted
	client = &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: ch.tlsConfig()}}
	if _, ok := testTarget(client, target); !ok {
		t.Fatal("доверенный сертификат должен проходить проверку")
	}
}

func testPool(t *testing.T) *ProxyPool {
	cfg := Config{MaxFails: 3, DataFile: filepath.Join(t.TempDir(), "sub", "pool.json"), MaxCustomList: 10, MaxAddPerCall: 5}
	return NewProxyPool(cfg, &Checker{roots: x509.NewCertPool()}, newGeoResolver())
}

func TestPoolFailuresAndPersistence(t *testing.T) {
	p := testPool(t)
	res := ProxyResult{Address: "77.88.55.60:1080", Protocol: "socks5", Targets: map[string]int64{"cbr": 100}, TargetCount: 1, DirectAccess: true}
	p.recordSuccess(res)
	p.recordSuccess(res)
	key := res.key()

	p.recordFailure(key)
	if r := p.get(key); r.ConsecutiveFails != 1 || r.TotalChecks != 3 || r.UptimePercent != 66.6 {
		t.Fatalf("после одного провала: %+v", r)
	}
	if len(p.GetProxies("", "", 0)) != 1 {
		t.Fatal("прокси с одним провалом ещё в выдаче")
	}
	p.recordFailure(key)
	if len(p.GetProxies("", "", 0)) != 0 {
		t.Fatal("прокси с двумя провалами подряд не должен выдаваться")
	}
	p.recordSuccess(res)
	if r := p.get(key); r.ConsecutiveFails != 0 {
		t.Fatal("успех сбрасывает счётчик провалов")
	}
	for i := 0; i < 3; i++ {
		p.recordFailure(key)
	}
	if p.Count() != 0 {
		t.Fatal("после MaxFails провалов подряд прокси удаляется")
	}

	// Сохранение / загрузка
	p.recordSuccess(res)
	p.mu.Lock()
	p.active["http://127.0.0.1:8080"] = ProxyResult{Address: "127.0.0.1:8080", Protocol: "http"} // «подложенная» запись
	p.mu.Unlock()
	p.SaveIfDirty()

	info, err := os.Stat(p.cfg.DataFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("файл пула должен иметь права 0600, а не %v", info.Mode().Perm())
	}

	p2 := NewProxyPool(p.cfg, p.checker, p.geo)
	if n := p2.Load(); n != 1 {
		t.Fatalf("должна загрузиться 1 корректная запись (локальный адрес отбрасывается), загружено %d", n)
	}
	if r := p2.get(key); r.ConsecutiveFails != 1 || r.TotalSuccess != 1 {
		t.Fatalf("загруженная запись: %+v", r)
	}
}

func TestAddCustomCandidatesFiltersAndLimits(t *testing.T) {
	p := testPool(t)
	p.customRunning.Store(true) // не запускаем реальную сетевую проверку
	text := "127.0.0.1:8080\n10.0.0.1:1080\n1.1.1.1:8080\n1.1.1.1:8080\n2.2.2.2:3128\n3.3.3.3:3128\n4.4.4.4:3128\n5.5.5.5:3128\n6.6.6.6:3128\n"
	n, now := p.AddCustomCandidates(text)
	if now {
		t.Error("пока идёт предыдущая проверка, новая не запускается")
	}
	if n != 5 {
		t.Errorf("ожидалось 5 принятых адресов (лимит на запрос, без локальных и дублей), принято %d", n)
	}
}

func TestRouter(t *testing.T) {
	p := testPool(t)
	cfg := Config{AdminToken: "secret-token-1234567890abcdef", PublicRPM: 1000, AdminRPM: 1000}
	h := withSecurityHeaders(newRouter(cfg, p))

	do := func(method, path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if r := do("GET", "/", ""); r.Code != 200 || !strings.Contains(r.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Errorf("дашборд: %d, CSP=%q", r.Code, r.Header().Get("Content-Security-Policy"))
	}
	if r := do("GET", "/static/app.js", ""); r.Code != 200 {
		t.Errorf("app.js: %d", r.Code)
	}
	if r := do("GET", "/api/proxies?target=nope", ""); r.Code != 400 {
		t.Errorf("неизвестный target: %d", r.Code)
	}
	if r := do("GET", "/api/proxies?target=cbr&format=txt", ""); r.Code != 200 {
		t.Errorf("список: %d", r.Code)
	}
	if r := do("GET", "/api/scan", ""); r.Code != 405 {
		t.Errorf("GET /api/scan должен быть запрещён: %d", r.Code)
	}
	if r := do("POST", "/api/scan", ""); r.Code != 401 {
		t.Errorf("POST /api/scan без токена: %d", r.Code)
	}
	if r := do("POST", "/api/scan", "wrong"); r.Code != 401 {
		t.Errorf("POST /api/scan с неверным токеном: %d", r.Code)
	}
	if r := do("POST", "/api/scan", ""); r.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("служебные эндпоинты не должны отдавать CORS-заголовки")
	}
	if r := do("POST", "/api/report?address=127.0.0.1:80", ""); r.Code != 400 {
		t.Errorf("report с локальным адресом: %d", r.Code)
	}
	if r := do("POST", "/api/report?address=1.2.3.4:8080", ""); r.Code != 404 {
		t.Errorf("report для отсутствующего прокси: %d", r.Code)
	}
}
