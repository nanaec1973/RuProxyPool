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

// ruCIDRTable хранит все российские IPv4 подсети (RIPE NCC / IPDeny),
// сгруппированные по первому октету IP для мгновенной фильтрации (за <1 микросекунду).
type ruCIDRTable struct {
	mu      sync.RWMutex
	loaded  bool
	buckets [256][]*net.IPNet
	count   int
}

var globalRUCIDRs = &ruCIDRTable{}

// EnsureLoaded загружает официальную базу российских IP-диапазонов (RIPE NCC + IPDeny)
func (t *ruCIDRTable) EnsureLoaded() {
	t.mu.RLock()
	if t.loaded && t.count > 1000 {
		t.mu.RUnlock()
		return
	}
	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.loaded && t.count > 1000 {
		return
	}

	client := &http.Client{Timeout: 12 * time.Second}
	var buckets [256][]*net.IPNet
	total := 0

	addCIDR := func(cidrStr string) {
		cidrStr = strings.TrimSpace(cidrStr)
		if cidrStr == "" || strings.HasPrefix(cidrStr, "#") {
			return
		}
		if !strings.Contains(cidrStr, "/") {
			cidrStr += "/32"
		}
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil || ipNet == nil {
			return
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			return
		}
		firstByte := ip4[0]
		buckets[firstByte] = append(buckets[firstByte], ipNet)
		total++
	}

	// Источник 1: IPDeny RU Zone (~11 480 российских подсетей)
	if resp, err := client.Get("https://www.ipdeny.com/ipblocks/data/countries/ru.zone"); err == nil {
		if resp.StatusCode == http.StatusOK {
			sc := bufio.NewScanner(resp.Body)
			for sc.Scan() {
				addCIDR(sc.Text())
			}
		}
		_ = resp.Body.Close()
	}

	// Источник 2 (резервный / дополнительный): Официальный реестр RIPE NCC по стране RU
	if total < 1000 {
		if resp, err := client.Get("https://stat.ripe.net/data/country-resource-list/data.json?resource=ru"); err == nil {
			if resp.StatusCode == http.StatusOK {
				var ripeData struct {
					Data struct {
						Resources struct {
							IPv4 []string `json:"ipv4"`
						} `json:"resources"`
					} `json:"data"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&ripeData); err == nil {
					for _, rng := range ripeData.Data.Resources.IPv4 {
						if strings.Contains(rng, "/") {
							addCIDR(rng)
						}
					}
				}
			}
			_ = resp.Body.Close()
		}
	}

	if total > 0 {
		t.buckets = buckets
		t.count = total
		t.loaded = true
		log.Printf("[GEO-RU] Загружено %d российских IPv4-подсетей (RIPE/IPDeny) для строгой фильтрации РФ", total)
	}
}

// IsRussianIP проверяет, принадлежит ли IPv4-адрес российскому пулу адресов
func (t *ruCIDRTable) IsRussianIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	t.mu.RLock()
	loaded := t.loaded
	bucket := t.buckets[ip4[0]]
	t.mu.RUnlock()

	if !loaded {
		return false
	}
	for _, netBlock := range bucket {
		if netBlock.Contains(ip4) {
			return true
		}
	}
	return false
}

type proxySource struct {
	Name     string
	URL      string
	Protocol string // "http", "socks5", "auto"
	Country  string // "RU" или "MIX"
	Type     string // "raw", "spys", "geonode"
}

var defaultSources = []proxySource{
	// 1. Прямые RU-источники
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
		Name:     "GeoNode-RU-Page1",
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

	// 2. Крупные мировые базы (~150 000+ адресов), из которых фильтр RIPE/RU вырезает ТОЛЬКО российские IP!
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
		Name:     "Prxchk-SOCKS5",
		URL:      "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Prxchk-HTTP",
		URL:      "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
		Protocol: "http",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Yakumo-SOCKS5",
		URL:      "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/socks5/global/socks5_checked.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Yakumo-HTTP",
		URL:      "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/http/global/http_checked.txt",
		Protocol: "http",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Mmpx12-SOCKS5",
		URL:      "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Mmpx12-HTTP",
		URL:      "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
		Protocol: "http",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Rdavydov-SOCKS5",
		URL:      "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
		Protocol: "socks5",
		Country:  "MIX",
		Type:     "raw",
	},
	{
		Name:     "Rdavydov-HTTP",
		URL:      "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
		Protocol: "http",
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

// FetchAllCandidates скачивает ~270 000+ адресов из 31 источника и оставляет
// СТРОГО ТОЛЬКО РОССИЙСКИЕ (RU) серверы (по базе подсетей RIPE NCC / IPDeny).
func FetchAllCandidates(customList []CandidateProxy, maxTotal int) ([]CandidateProxy, int, int) {
	globalRUCIDRs.EnsureLoaded()

	var (
		mu             sync.Mutex
		seen           = make(map[string]bool)
		ruProxies      []CandidateProxy
		rawTotalLoaded int
		skippedForeign int
	)

	addCandidate := func(c CandidateProxy) {
		addr := strings.TrimSpace(c.Address)
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host == "" || port == "" || net.ParseIP(host) == nil {
			return
		}

		// СТРОГИЙ ФИЛЬТР РФ: проверяем принадлежность IP к российским подсетям RIPE/IPDeny
		isRU := c.Country == "RU" || c.Source == "Custom" || globalRUCIDRs.IsRussianIP(host)
		if !isRU {
			mu.Lock()
			skippedForeign++
			mu.Unlock()
			return
		}

		c.Country = "RU"
		c.Address = addr

		// Определяем протоколы для проверки этого российского сервера
		var protos []string
		switch c.Protocol {
		case "socks5":
			protos = []string{"socks5", "http"}
		case "http":
			protos = []string{"http", "socks5"}
		default:
			protos = []string{"socks5", "http"}
		}

		mu.Lock()
		defer mu.Unlock()
		for _, p := range protos {
			key := p + "://" + addr
			if !seen[key] {
				seen[key] = true
				itemCopy := c
				itemCopy.Protocol = p
				ruProxies = append(ruProxies, itemCopy)
			}
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

	for _, items := range resultsBySource {
		rawTotalLoaded += len(items)
		for _, item := range items {
			addCandidate(item)
		}
	}

	if maxTotal > 0 && len(ruProxies) > maxTotal {
		ruProxies = ruProxies[:maxTotal]
	}

	log.Printf("[FETCHER] Проанализировано мировых списков: %d адресов | Отсеяно иностранных: %d | ОСТАВЛЕНО ЧИСТЫХ RU-КАНДИДАТОВ: %d",
		rawTotalLoaded, skippedForeign, len(ruProxies))
	return ruProxies, rawTotalLoaded, skippedForeign
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

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
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
			if cc == "RU" {
				country = "RU"
			} else {
				continue // В Spys.me сразу пропускаем не-RU строки
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
		out = append(out, CandidateProxy{
			Address:  fmt.Sprintf("%s:%s", item.IP, item.Port),
			Protocol: proto,
			Country:  "RU",
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
