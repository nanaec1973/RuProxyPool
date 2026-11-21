package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type geoInfo struct {
	CountryCode string
	City        string
	Region      string
	ISP         string
}

// geoResolver определяет город и провайдера по IP. Бесплатные API жёстко лимитированы
// (ip-api.com — 45 запросов/мин), поэтому запросы идут не чаще одного в interval,
// а результат кэшируется. Решение «РФ или нет» принимается НЕ здесь, а по таблице
// подсетей RIPE/IPDeny — гео-API нужен только для красивого названия города.
type geoResolver struct {
	client   *http.Client
	interval time.Duration

	mu       sync.Mutex
	cache    map[string]geoInfo
	lastCall time.Time
}

func newGeoResolver() *geoResolver {
	return &geoResolver{
		client:   &http.Client{Timeout: 4 * time.Second},
		interval: 1500 * time.Millisecond,
		cache:    make(map[string]geoInfo),
	}
}

func (g *geoResolver) Cached(ip string) (geoInfo, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	info, ok := g.cache[ip]
	return info, ok
}

// Lookup делает не больше одного внешнего запроса за interval. Если лимит исчерпан
// или оба API недоступны — возвращает ok=false (данные просто дозаполнятся позже).
func (g *geoResolver) Lookup(ip string) (geoInfo, bool) {
	if info, ok := g.Cached(ip); ok {
		return info, true
	}

	g.mu.Lock()
	if time.Since(g.lastCall) < g.interval {
		g.mu.Unlock()
		return geoInfo{}, false
	}
	g.lastCall = time.Now()
	if len(g.cache) > 50000 { // защита от бесконечного роста памяти
		g.cache = make(map[string]geoInfo)
	}
	g.mu.Unlock()

	info, ok := g.fromIPAPI(ip)
	if !ok {
		info, ok = g.fromIPWho(ip)
	}
	if !ok {
		return geoInfo{}, false
	}
	if info.City == "" {
		info.City = info.Region
	}
	g.mu.Lock()
	g.cache[ip] = info
	g.mu.Unlock()
	return info, true
}

func (g *geoResolver) fromIPAPI(ip string) (geoInfo, bool) {
	// Бесплатный тариф ip-api.com работает только по HTTP. Это допустимо:
	// данные отсюда идут лишь в поля city/region/isp и ни на что не влияют.
	u := fmt.Sprintf("http://ip-api.com/json/%s?lang=ru&fields=status,countryCode,regionName,city,isp", ip)
	resp, err := g.client.Get(u)
	if err != nil {
		return geoInfo{}, false
	}
	defer resp.Body.Close()
	var data struct {
		Status      string `json:"status"`
		CountryCode string `json:"countryCode"`
		RegionName  string `json:"regionName"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&data); err != nil || data.Status != "success" {
		return geoInfo{}, false
	}
	return geoInfo{CountryCode: data.CountryCode, City: data.City, Region: data.RegionName, ISP: data.ISP}, true
}

func (g *geoResolver) fromIPWho(ip string) (geoInfo, bool) {
	resp, err := g.client.Get(fmt.Sprintf("https://ipwho.is/%s?lang=ru", ip))
	if err != nil {
		return geoInfo{}, false
	}
	defer resp.Body.Close()
	var data struct {
		Success     bool   `json:"success"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Connection  struct {
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&data); err != nil || !data.Success {
		return geoInfo{}, false
	}
	return geoInfo{CountryCode: data.CountryCode, City: data.City, Region: data.Region, ISP: data.Connection.ISP}, true
}
