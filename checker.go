package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// CheckCandidate проверяет один прокси-сервер:
// 1. Быстрый TCP-пингователь (отсекает мертвые узлы за 1.8 сек).
// 2. Пробный запрос к Яндексу / Мосгорсуду через прокси.
// 3. При успехе — параллельная проверка доступности всех ключевых ресурсов РФ за 4 сек.
func CheckCandidate(c CandidateProxy) (*ProxyResult, bool) {
	// Шаг 1: Быстрый TCP-коннект
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

	// Шаг 2: Создаем HTTP-клиент через прокси (HTTP или SOCKS5)
	client, err := buildProxyHTTPClient(c.Address, c.Protocol, 4500*time.Millisecond)
	if err != nil {
		return nil, false
	}

	// Быстрая первичная проверка: пропускает ли прокси трафик к РФ (Яндекс или Мосгорсуд параллельно)
	var (
		yaLat, mgsLat int64
		yaOK, mgsOK   bool
		probeWg       sync.WaitGroup
	)
	probeWg.Add(2)
	go func() {
		defer probeWg.Done()
		yaLat, yaOK = testTargetURL(client, "https://ya.ru")
	}()
	go func() {
		defer probeWg.Done()
		mgsLat, mgsOK = testTargetURL(client, "https://mos-gorsud.ru")
	}()
	probeWg.Wait()

	if !yaOK && !mgsOK {
		return nil, false
	}

	var (
		mu           sync.Mutex
		targets      = make(map[string]int64)
		totalLatency int64
	)

	if yaOK {
		targets["ya"] = yaLat
		totalLatency += yaLat
	}
	if mgsOK {
		targets["mosgorsud"] = mgsLat
		totalLatency += mgsLat
	}

	// Шаг 3: Параллельно проверяем остальные ключевые российские сайты
	var wg sync.WaitGroup
	for _, t := range TargetList {
		if t.Key == "ya" || t.Key == "mosgorsud" {
			continue
		}
		wg.Add(1)
		go func(tr TargetResource) {
			defer wg.Done()
			if lat, ok := testTargetURL(client, tr.URL); ok {
				mu.Lock()
				targets[tr.Key] = lat
				totalLatency += lat
				mu.Unlock()
			}
		}(t)
	}
	wg.Wait()

	if len(targets) == 0 {
		return nil, false
	}

	avgLat := totalLatency / int64(len(targets))
	directGov := targets["mosgorsud"] > 0 || targets["gosuslugi"] > 0 || targets["nalog"] > 0 || targets["cbr"] > 0

	country := c.Country
	if country == "" || country == "MIX" {
		if directGov {
			country = "RU/CIS"
		} else {
			country = "INT"
		}
	}

	return &ProxyResult{
		Address:       c.Address,
		Protocol:      c.Protocol,
		Country:       country,
		Source:        c.Source,
		TCPPingMs:     tcpPing,
		AvgLatencyMs:  avgLat,
		Targets:       targets,
		TargetCount:   len(targets),
		DirectAccess:  directGov,
		LastCheckedAt: time.Now(),
	}, true
}

func testTargetURL(client *http.Client, targetURL string) (int64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 4200*time.Millisecond)
	defer cancel()

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
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

	_, _ = io.CopyN(io.Discard, resp.Body, 256)
	elapsed := time.Since(start).Milliseconds()
	if elapsed == 0 {
		elapsed = 1
	}

	// Считаем ресурс доступным, если код ответа 2xx или 3xx (не 403 Geo-Block и не 5xx)
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return elapsed, true
	}
	return 0, false
}

func buildProxyHTTPClient(proxyAddr, proto string, timeout time.Duration) (*http.Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	if proto == "socks5" {
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialSOCKS5(ctx, proxyAddr, addr)
			},
			TLSClientConfig:       tlsConfig,
			TLSHandshakeTimeout:   3500 * time.Millisecond,
			ResponseHeaderTimeout: 3500 * time.Millisecond,
			DisableKeepAlives:     true,
		}
		return &http.Client{
			Transport: transport,
			Timeout:   timeout,
		}, nil
	}

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   3500 * time.Millisecond,
		ResponseHeaderTimeout: 3500 * time.Millisecond,
		DisableKeepAlives:     true,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
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

	return conn, nil
}
