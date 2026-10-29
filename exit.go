package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type geoInfo struct {
	CountryCode string
	City        string
	Region      string
	ISP         string
}

type geoCacheEntry struct {
	Info      geoInfo
	ExpiresAt time.Time
}

var geoCache sync.Map // actual exit IP -> geoCacheEntry; failures are never cached as RU

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// readJSON requires a complete, bounded, successful response. A truncated prefix
// must never turn into a successful exit check.
func readJSON(ctx context.Context, client httpDoer, endpoint string, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}
	const maxBody = 32 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		return fmt.Errorf("JSON response too large")
	}
	return json.Unmarshal(body, result)
}

func publicIP(raw string) bool {
	ip := net.ParseIP(raw)
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func lookupRussianCity(ip string) (geoInfo, bool) {
	if !publicIP(ip) {
		return geoInfo{}, false
	}
	if cached, ok := geoCache.Load(ip); ok {
		entry := cached.(geoCacheEntry)
		if time.Now().Before(entry.ExpiresAt) {
			return entry.Info, entry.Info.CountryCode == "RU"
		}
		geoCache.Delete(ip)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()
	// No environment proxy here: locate the explicit exit IP, from the scanner.
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3500 * time.Millisecond}
	defer client.CloseIdleConnections()
	info, ok := lookupGeo(ctx, client, ip)
	if !ok {
		return geoInfo{}, false
	}
	geoCache.Store(ip, geoCacheEntry{Info: info, ExpiresAt: time.Now().Add(30 * time.Minute)})
	return info, info.CountryCode == "RU"
}

func lookupGeo(ctx context.Context, client httpDoer, ip string) (geoInfo, bool) {
	var data struct {
		Success     bool   `json:"success"`
		IP          string `json:"ip"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Connection  struct {
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if !publicIP(ip) || readJSON(ctx, client, "https://ipwho.is/"+url.PathEscape(ip)+"?lang=ru", &data) != nil ||
		!data.Success || !net.ParseIP(data.IP).Equal(net.ParseIP(ip)) || len(data.CountryCode) != 2 {
		return geoInfo{}, false
	}
	return geoInfo{CountryCode: strings.ToUpper(data.CountryCode), City: data.City,
		Region: data.Region, ISP: data.Connection.ISP}, true
}

func verifyRussianExit(client *http.Client) (string, geoInfo, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return verifyProxyExit(ctx, client, lookupRussianCity)
}

func verifyProxyExit(ctx context.Context, client httpDoer, resolve func(string) (geoInfo, bool)) (string, geoInfo, bool) {
	// Query through this exact proxy. An entry address or a RIPE allocation is
	// insufficient: a Russian entry may forward to an exit in another country.
	for _, endpoint := range []string{"https://api.ipify.org?format=json", "https://api64.ipify.org?format=json"} {
		var data struct {
			IP string `json:"ip"`
		}
		if readJSON(ctx, client, endpoint, &data) != nil || !publicIP(data.IP) {
			continue
		}
		info, isRU := resolve(data.IP)
		if !isRU || info.CountryCode != "RU" {
			return "", geoInfo{}, false
		}
		return data.IP, info, true
	}
	return "", geoInfo{}, false
}
