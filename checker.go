package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Checker проверяет прокси-кандидатов. Все HTTPS-запросы идут с ПОЛНОЙ проверкой
// сертификатов: прокси, который подменяет сертификат или вмешивается в трафик (MITM),
// не проходит проверку и не попадает в пул.
type Checker struct {
	roots      *x509.CertPool
	ownIP      atomic.Value // string: наш внешний IP (чтобы отсеять «прозрачные» прокси)
	checkIPURL string
}

func NewChecker(certsDir, checkIPURL string) *Checker {
	c := &Checker{roots: loadRootCAs(certsDir), checkIPURL: checkIPURL}
	c.ownIP.Store("")
	if checkIPURL != "" {
		go func() { // в фоне, чтобы не задерживать запуск HTTP-сервера
			ip := c.detectOwnIP()
			if ip == "" {
				log.Printf("[CHECKER] Не удалось определить собственный внешний IP — проверка на прозрачные прокси ограничена")
				return
			}
			c.ownIP.Store(ip)
		}()
	}
	return c
}

// loadRootCAs берёт системные корневые сертификаты и добавляет к ним файлы *.pem / *.crt
// из certsDir (например, Russian Trusted Root CA от Минцифры, которым подписаны
// сертификаты части российских сайтов).
func loadRootCAs(dir string) *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if dir == "" {
		return pool
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	added := 0
	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f))
		if ext != ".pem" && ext != ".crt" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if pool.AppendCertsFromPEM(data) {
			added++
			log.Printf("[CHECKER] Добавлен корневой сертификат: %s", filepath.Base(f))
		} else {
			log.Printf("[CHECKER] ⚠️  Файл %s не похож на PEM-сертификат, пропущен", filepath.Base(f))
		}
	}
	if added == 0 {
		log.Printf("[CHECKER] Дополнительных корневых сертификатов нет (%s) — используются только системные", dir)
	}
	return pool
}

func (c *Checker) tlsConfig() *tls.Config {
	return &tls.Config{RootCAs: c.roots, MinVersion: tls.VersionTLS12}
}

func (c *Checker) detectOwnIP() string {
	client := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{TLSClientConfig: c.tlsConfig()}}
	for i := 0; i < 3; i++ {
		if ip := fetchIP(client, c.checkIPURL); ip != "" {
			return ip
		}
		time.Sleep(time.Second)
	}
	return ""
}

func fetchIP(client *http.Client, u string) string {
	resp, err := client.Get(u)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	ip := net.ParseIP(strings.TrimSpace(string(b)))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// expandProtocols превращает кандидата с неизвестным протоколом в два (http и socks5).
// Если протокол известен — проверяем только его: это вдвое ускоряет сканирование.
func expandProtocols(c CandidateProxy) []CandidateProxy {
	switch c.Protocol {
	case "http", "socks5":
		return []CandidateProxy{c}
	default:
		a, b := c, c
		a.Protocol, b.Protocol = "socks5", "http"
		return []CandidateProxy{a, b}
	}
}

// CheckCandidate проверяет один прокси-сервер:
//  1. Быстрый TCP-коннект (отсекает мёртвые узлы за 1.8 сек).
//  2. Пробный HTTPS-запрос к Яндексу и Мосгорсуду (с проверкой сертификата и содержимого).
//  3. Параллельная проверка остальных ресурсов РФ + определение реального IP выхода.
//  4. Прокси принимается, только если он открыл хотя бы один внутрироссийский портал
//     и реально выходит в интернет с российского IP.
func (ch *Checker) CheckCandidate(c CandidateProxy) (*ProxyResult, bool) {
	if c.Protocol != "http" && c.Protocol != "socks5" {
		return nil, false
	}
	if !isAllowedProxyAddr(c.Address) {
		return nil, false
	}

	tcpStart := time.Now()
	conn, err := net.DialTimeout("tcp", c.Address, 1800*time.Millisecond)
	if err != nil {
		return nil, false
	}
	_ = conn.Close()
	tcpPing := time.Since(tcpStart).Milliseconds()
	if tcpPing == 0 {
		tcpPing = 1
	}

	client, err := ch.buildProxyHTTPClient(c.Address, c.Protocol, 6*time.Second)
	if err != nil {
		return nil, false
	}

	ya, _ := targetByKey("ya")
	mgs, _ := targetByKey("mosgorsud")
	var (
		yaLat, mgsLat int64
		yaOK, mgsOK   bool
		probeWg       sync.WaitGroup
	)
	probeWg.Add(2)
	go func() { defer probeWg.Done(); yaLat, yaOK = testTarget(client, ya) }()
	go func() { defer probeWg.Done(); mgsLat, mgsOK = testTarget(client, mgs) }()
	probeWg.Wait()
	if !yaOK && !mgsOK {
		return nil, false
	}

	var (
		mu           sync.Mutex
		targets      = make(map[string]int64)
		totalLatency int64
		exitIP       string
		wg           sync.WaitGroup
	)
	if yaOK {
		targets["ya"] = yaLat
		totalLatency += yaLat
	}
	if mgsOK {
		targets["mosgorsud"] = mgsLat
		totalLatency += mgsLat
	}

	for _, t := range TargetList {
		if t.Key == "ya" || t.Key == "mosgorsud" {
			continue
		}
		wg.Add(1)
		go func(tr TargetResource) {
			defer wg.Done()
			if lat, ok := testTarget(client, tr); ok {
				mu.Lock()
				targets[tr.Key] = lat
				totalLatency += lat
				mu.Unlock()
			}
		}(t)
	}
	if ch.checkIPURL != "" {
		wg.Add(1)
		go func() { defer wg.Done(); exitIP = fetchIP(client, ch.checkIPURL) }()
	}
	wg.Wait()

	directGov := targets["mosgorsud"] > 0 || targets["gosuslugi"] > 0 || targets["nalog"] > 0 ||
		targets["cbr"] > 0 || targets["mos"] > 0
	ruInfra := directGov || targets["sber"] > 0 || targets["rzd"] > 0
	if !ruInfra {
		return nil, false
	}

	// Прозрачный прокси: сайты видят наш собственный IP — такой прокси бесполезен.
	if own, _ := ch.ownIP.Load().(string); exitIP != "" && own != "" && exitIP == own {
		return nil, false
	}
	// Страну определяем по IP ВЫХОДА (он может отличаться от адреса входа),
	// а если его узнать не удалось — по адресу входа. Только по таблице RIPE/IPDeny.
	host, _, _ := net.SplitHostPort(c.Address)
	geoIP := host
	if exitIP != "" {
		geoIP = exitIP
	}
	if !globalRUCIDRs.IsRussianIP(geoIP) {
		return nil, false
	}

	return &ProxyResult{
		Address:       c.Address,
		Protocol:      c.Protocol,
		Country:       "RU",
		ExitIP:        exitIP,
		Source:        c.Source,
		TCPPingMs:     tcpPing,
		AvgLatencyMs:  totalLatency / int64(len(targets)),
		Targets:       targets,
		TargetCount:   len(targets),
		DirectAccess:  directGov,
		LastCheckedAt: time.Now(),
	}, true
}

// testTarget запрашивает ресурс через прокси и проверяет, что пришла настоящая страница.
func testTarget(client *http.Client, t TargetResource) (int64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", t.URL, nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	elapsed := time.Since(start).Milliseconds()
	if elapsed == 0 {
		elapsed = 1
	}
	if !evaluateResponse(t, resp.StatusCode, resp.Request.URL, body) {
		return 0, false
	}
	return elapsed, true
}

// Признаки страниц-заглушек, капч и анти-бот защиты.
var blockMarkers = []string{
	"remote_addr", "http_x_forwarded_for", // эхо-заглушки фейковых прокси
	"checking your browser", "проверка браузера", "проверяем ваш браузер",
	"доступ ограничен", "access denied", "are you a robot", "вы не робот",
}

// evaluateResponse решает, засчитывать ли ответ как успешный. Чистая функция — покрыта тестами.
func evaluateResponse(t TargetResource, status int, finalURL *url.URL, body []byte) bool {
	if status < 200 || status >= 300 || len(body) < 200 {
		return false
	}
	if finalURL != nil {
		if strings.Contains(strings.ToLower(finalURL.String()), "captcha") {
			return false
		}
		// Редирект на чужой домен — признак подмены (реклама, фишинг-заглушка провайдера).
		if want, err := url.Parse(t.URL); err == nil && !sameSite(want.Hostname(), finalURL.Hostname()) {
			return false
		}
	}
	lower := strings.ToLower(string(body))
	for _, m := range blockMarkers {
		if strings.Contains(lower, m) {
			return false
		}
	}
	if len(t.Markers) == 0 {
		return true
	}
	for _, m := range t.Markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// sameSite: "www.cbr.ru" и "cbr.ru" считаются одним сайтом, как и поддомены.
func sameSite(a, b string) bool {
	a = strings.TrimPrefix(strings.ToLower(a), "www.")
	b = strings.TrimPrefix(strings.ToLower(b), "www.")
	return a == b || strings.HasSuffix(b, "."+a) || strings.HasSuffix(a, "."+b)
}

func (ch *Checker) buildProxyHTTPClient(proxyAddr, proto string, timeout time.Duration) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig:        ch.tlsConfig(),
		TLSHandshakeTimeout:    4 * time.Second,
		ResponseHeaderTimeout:  4 * time.Second,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 * 1024,
	}
	switch proto {
	case "socks5":
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialSOCKS5(ctx, proxyAddr, addr)
		}
	case "http":
		proxyURL, err := url.Parse("http://" + proxyAddr)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	default:
		return nil, fmt.Errorf("unknown protocol %q", proto)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("redirect to non-https")
			}
			return nil
		},
	}, nil
}

// dialSOCKS5 реализует минималистичный RFC 1928 SOCKS5 клиент на чистом Go без внешних библиотек
func dialSOCKS5(ctx context.Context, proxyAddr, targetAddr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(4 * time.Second)
	}
	_ = conn.SetDeadline(deadline)

	// 1. Greeting: VER=5, NMETHODS=1, METHOD=0 (No Auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		return nil, err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		_ = conn.Close()
		return nil, errors.New("socks5 auth rejected")
	}

	// 2. Connect Request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP=3 (Domain) или 1 (IPv4)
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid port: %s", portStr)
	}

	reqBuf := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		reqBuf = append(reqBuf, 0x01)
		reqBuf = append(reqBuf, ip.To4()...)
	} else {
		if len(host) > 255 {
			_ = conn.Close()
			return nil, errors.New("domain too long")
		}
		reqBuf = append(reqBuf, 0x03, byte(len(host)))
		reqBuf = append(reqBuf, []byte(host)...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portNum))
	reqBuf = append(reqBuf, portBytes...)

	if _, err := conn.Write(reqBuf); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// 3. Читаем заголовок ответа SOCKS5
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect failed: code %d", hdr[1])
	}

	// Пропускаем BND.ADDR + BND.PORT
	var skipLen int
	switch hdr[3] {
	case 0x01: // IPv4
		skipLen = 4 + 2
	case 0x04: // IPv6
		skipLen = 16 + 2
	case 0x03: // Domain
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			_ = conn.Close()
			return nil, err
		}
		skipLen = int(lenByte[0]) + 2
	default:
		_ = conn.Close()
		return nil, errors.New("unknown socks5 atyp")
	}

	discard := make([]byte, skipLen)
	if _, err := io.ReadFull(conn, discard); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Рукопожатие закончено: дальше таймауты контролирует http.Transport.
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
