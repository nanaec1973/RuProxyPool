package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var ipPortRegex = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})\b`)

type proxySource struct {
	Name     string
	URL      string
	Protocol string // "http", "socks5", "auto"
	Country  string // "RU" или "MIX"
	Type     string // "raw", "spys", "geonode"
}

var defaultSources = []proxySource{
	// 1. Приоритетные RU-источники
	{
		Name:     "Proxifly-RU",
		URL:      "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/countries/RU/data.txt",
		Protocol: "auto",
		Country:  "RU",
		Type:     "raw",
	},
	{
		Name:     "ProxyScrape-RU-SOCKS5",
		URL:      "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=RU&ssl=all&anonymity=all",
		Protocol: "socks5",
		Country:  "RU",
		Type:     "raw",
	},
	{
		Name:     "ProxyScrape-RU-HTTP",
		URL:      "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=RU&ssl=all&anonymity=all",
		Protocol: "http",
		Country:  "RU",
		Type:     "raw",
	},
	{
		Name:     "GeoNode-RU",
		URL:      "https://proxylist.geonode.com/api/proxy-list?country=RU&limit=500&page=1&sort_by=lastChecked&sort_type=desc",
		Protocol: "auto",
		Country:  "RU",
		Type:     "geonode",
	},
	{
		Name:     "SpysMe-SOCKS",
		URL:      "https://spys.me/socks.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "spys",
	},
	{
		Name:     "SpysMe-HTTP",
		URL:      "https://spys.me/proxy.txt",
		Protocol: "http",
		Country:  "MIX",
		Type:     "spys",
	},

	// 2. Все 16 крупных мировых источников из proxy_checker.go (~20 000+ адресов)
	{
		Name:     "OpenProxyList-SOCKS5",
		URL:      "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "OpenProxyList-HTTPS",
		URL:      "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
		Protocol: "http",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "TheSpeedX-SOCKS5",
		URL:      "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Hookzof-SOCKS5",
		URL:      "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Monosans-All",
		URL:      "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Monosans-HTTP",
		URL:      "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
		Protocol: "http",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Proxifly-SOCKS5",
		URL:      "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Proxifly-HTTP",
		URL:      "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
		Protocol: "http",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Zaeem20-SOCKS5",
		URL:      "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Vakhov-SOCKS5",
		URL:      "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Vakhov-HTTP",
		URL:      "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
		Protocol: "http",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "ErcinDedeoglu-SOCKS5",
		URL:      "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Sunny9577-SOCKS5",
		URL:      "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "ALIILAPRO-SOCKS5",
		URL:      "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "ProxyScrape-Global-SOCKS5",
		URL:      "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=5000",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "ProxyScrape-Global-HTTP",
		URL:      "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000",
		Protocol: "http",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "TheSpeedX-HTTP",
		URL:      "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
		Protocol: "http",
		Country:  "MIX",
		Type:     "raw",
	},
}

// FetchAllCandidates параллельно собирает ~20 000+ адресов из всех источников,
// ставя в начало очереди российские (RU) и ранее проверенные серверы.
func FetchAllCandidates(customList []CandidateProxy, maxTotal int) []CandidateProxy {
	var (
		mu         sync.Mutex
		seen       = make(map[string]bool)
		ruProxies  []CandidateProxy
		mixProxies []CandidateProxy
	)

	addCandidate := func(c CandidateProxy) {
		addr := strings.TrimSpace(c.Address)
		if !isValidIPPort(addr) {
			return
		}
		if c.Protocol == "" || c.Protocol == "auto" {
			c.Protocol = "socks5"
		}
		key := c.Protocol + "://" + addr

		mu.Lock()
		defer mu.Unlock()
		if seen[key] {
			return
		}
		seen[key] = true
		c.Address = addr

		if c.Country == "RU" || c.Source == "Custom" {
			ruProxies = append(ruProxies, c)
		} else {
			mixProxies = append(mixProxies, c)
		}
	}

	for _, c := range customList {
		addCandidate(c)
	}

	var wg sync.WaitGroup
	client := &http.Client{Timeout: 10 * time.Second}
	resultsBySource := make([][]CandidateProxy, len(defaultSources))

	for idx, src := range defaultSources {
		wg.Add(1)
		go func(i int, s proxySource) {
			defer wg.Done()
			items, err := fetchFromSource(client, s)
			if err != nil {
				log.Printf("[FETCHER] Источник %s пропущен: %v", s.Name, err)
				return
			}
			resultsBySource[i] = items
		}(idx, src)
	}

	wg.Wait()

	// Объединяем строго в порядке приоритета источников
	for _, items := range resultsBySource {
		for _, item := range items {
			addCandidate(item)
		}
	}

	result := make([]CandidateProxy, 0, len(ruProxies)+len(mixProxies))
	result = append(result, ruProxies...)

	if maxTotal <= 0 {
		result = append(result, mixProxies...)
	} else {
		remaining := maxTotal - len(result)
		if remaining > 0 {
			if len(mixProxies) > remaining {
				result = append(result, mixProxies[:remaining]...)
			} else {
				result = append(result, mixProxies...)
			}
		}
	}

	log.Printf("[FETCHER] Собрано уникальных серверов из %d источников: %d (Приоритетных RU: %d, Глобальных: %d)",
		len(defaultSources), len(result), len(ruProxies), len(result)-len(ruProxies))
	return result
}

func fetchFromSource(client *http.Client, s proxySource) ([]CandidateProxy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; RuProxyPool/2.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // До 10 МБ
	if err != nil {
		return nil, err
	}
	body := string(bodyBytes)

	switch s.Type {
	case "geonode":
		return parseGeoNodeJSON(body, s.Name)
	case "spys":
		return parseSpysTxt(body, s.Protocol, s.Name), nil
	default:
		return parseRawLines(body, s.Protocol, s.Country, s.Name), nil
	}
}

func parseRawLines(body, defaultProto, defaultCountry, sourceName string) []CandidateProxy {
	var out []CandidateProxy
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		proto := defaultProto
		if strings.HasPrefix(line, "socks5://") {
			proto = "socks5"
			line = strings.TrimPrefix(line, "socks5://")
		} else if strings.HasPrefix(line, "socks4://") {
			continue
		} else if strings.HasPrefix(line, "http://") {
			proto = "http"
			line = strings.TrimPrefix(line, "http://")
		} else if strings.HasPrefix(line, "https://") {
			proto = "http"
			line = strings.TrimPrefix(line, "https://")
		}

		matches := ipPortRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			out = append(out, CandidateProxy{
				Address:  matches[1],
				Protocol: proto,
				Country:  defaultCountry,
				Source:   sourceName,
			})
		}
	}
	return out
}

func parseSpysTxt(body, proto, sourceName string) []CandidateProxy {
	var out []CandidateProxy
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		matches := ipPortRegex.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}
		addr := matches[1]
		country := "MIX"
		parts := strings.Fields(line)
		if len(parts) >= 2 && len(parts[1]) >= 2 {
			cc := parts[1][:2]
			if cc == "RU" || cc == "BY" || cc == "KZ" {
				country = cc
			}
		}
		out = append(out, CandidateProxy{
			Address:  addr,
			Protocol: proto,
			Country:  country,
			Source:   sourceName,
		})
	}
	return out
}

type geoNodeResponse struct {
	Data []struct {
		IP        string   `json:"ip"`
		Port      string   `json:"port"`
		Protocols []string `json:"protocols"`
		Country   string   `json:"country"`
	} `json:"data"`
}

func parseGeoNodeJSON(body, sourceName string) ([]CandidateProxy, error) {
	var parsed geoNodeResponse
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return nil, err
	}
	var out []CandidateProxy
	for _, item := range parsed.Data {
		proto := "socks5"
		for _, p := range item.Protocols {
			if p == "socks5" {
				proto = "socks5"
				break
			}
			if p == "http" || p == "https" {
				proto = "http"
				break
			}
		}
		country := item.Country
		if country == "" {
			country = "RU"
		}
		out = append(out, CandidateProxy{
			Address:  fmt.Sprintf("%s:%s", item.IP, item.Port),
			Protocol: proto,
			Country:  country,
			Source:   sourceName,
		})
	}
	return out, nil
}

func isValidIPPort(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil
}
