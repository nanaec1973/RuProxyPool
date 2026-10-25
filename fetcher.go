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
	Type     string // "raw", "spys", "geonode", "monosans_geo"
}

var defaultSources = []proxySource{
	// Специализированные RU-источники (высший приоритет)
	{
		Name:     "ProxyScrape-RU-HTTP",
		URL:      "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=RU&ssl=all&anonymity=all",
		Protocol: "http",
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
		Name:     "Proxifly-RU",
		URL:      "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/countries/RU/data.txt",
		Protocol: "auto",
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
		Name:     "SpysMe-HTTP",
		URL:      "https://spys.me/proxy.txt",
		Protocol: "http",
		Country:  "MIX",
		Type:     "spys",
	},
	{
		Name:     "SpysMe-SOCKS",
		URL:      "https://spys.me/socks.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "spys",
	},
	// Крупные глобальные пулы (несколько тысяч адресов)
	{
		Name:     "Monosans-HTTP",
		URL:      "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
		Protocol: "http",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Monosans-SOCKS5",
		URL:      "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "TheSpeedX-HTTP",
		URL:      "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
		Protocol: "http",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "TheSpeedX-SOCKS5",
		URL:      "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "JetKai-HTTP",
		URL:      "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
		Protocol: "http",
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
}

// FetchAllCandidates параллельно собирает тысячи адресов из всех источников,
// ставя в начало списка российские (RU) и пользовательские адреса.
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
			c.Protocol = "http"
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

	// Сначала добавляем пользовательские прокси
	for _, c := range customList {
		addCandidate(c)
	}

	var wg sync.WaitGroup
	client := &http.Client{Timeout: 12 * time.Second}

	for _, src := range defaultSources {
		wg.Add(1)
		go func(s proxySource) {
			defer wg.Done()
			items, err := fetchFromSource(client, s)
			if err != nil {
				log.Printf("[FETCHER] Источник %s недоступен: %v", s.Name, err)
				return
			}
			for _, item := range items {
				addCandidate(item)
			}
		}(src)
	}

	wg.Wait()

	// Сначала идут все приоритетные RU-адреса, затем остальные до лимита maxTotal
	result := make([]CandidateProxy, 0, len(ruProxies)+len(mixProxies))
	result = append(result, ruProxies...)

	remaining := maxTotal - len(result)
	if remaining > 0 {
		if len(mixProxies) > remaining {
			result = append(result, mixProxies[:remaining]...)
		} else {
			result = append(result, mixProxies...)
		}
	}

	log.Printf("[FETCHER] Собрано кандидатов: %d (из них RU/Приоритетных: %d, Глобальных: %d)",
		len(result), len(ruProxies), len(result)-len(ruProxies))
	return result
}

func fetchFromSource(client *http.Client, s proxySource) ([]CandidateProxy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; RuProxyPool/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // До 5 МБ
	if err != nil {
		return nil, err
	}
	body := string(bodyBytes)

	switch s.Type {
	case "geonode":
		return parseGeoNodeJSON(body, s.Name)
	case "spys":
		return parseSpysTxt(body, s.Protocol, s.Name), nil
	case "monosans_geo":
		return parseMonosansGeo(body, s.Protocol, s.Name), nil
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

// Формат spys.me: "31.40.248.2:8080 RU-N-S! +"
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

// Формат monosans geolocation: "1.2.3.4:8080|RU|..."
func parseMonosansGeo(body, proto, sourceName string) []CandidateProxy {
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
		upper := strings.ToUpper(line)
		if strings.Contains(upper, "|RU|") || strings.Contains(upper, "RUSSIA") || strings.Contains(upper, " RU ") {
			country = "RU"
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
		proto := "http"
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
