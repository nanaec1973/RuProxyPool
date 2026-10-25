package main

import (
	"log"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// PoolStats хранит сводную статистику сканера для API и веб-дашборда
type PoolStats struct {
	RawAnalyzed     int              `json:"raw_analyzed"`
	ForeignFiltered int              `json:"foreign_filtered"`
	TotalCandidates int              `json:"total_candidates"`
	ScannedCount    int              `json:"scanned_count"`
	AliveCount      int              `json:"alive_count"`
	DirectGovCount  int              `json:"direct_gov_count"`
	ScanInProgress  bool             `json:"scan_in_progress"`
	LastScanStarted time.Time        `json:"last_scan_started"`
	LastScanEnded   time.Time        `json:"last_scan_ended"`
	ByTarget        map[string]int   `json:"by_target"`
	TargetsMeta     []TargetResource `json:"targets_meta"`
}

// ProxyPool управляет списком рабочих серверов и фоновым сканированием
type ProxyPool struct {
	mu              sync.RWMutex
	active          map[string]ProxyResult // ключ: protocol://ip:port
	customList      []CandidateProxy
	rawAnalyzed     int
	foreignFiltered int
	totalCandidates int
	scannedCount    int64
	scanInProgress  bool
	lastScanStarted time.Time
	lastScanEnded   time.Time
	workers         int
	maxCandidates   int
}

func NewProxyPool(workers, maxCandidates int) *ProxyPool {
	return &ProxyPool{
		active:        make(map[string]ProxyResult),
		workers:       workers,
		maxCandidates: maxCandidates,
	}
}

// StartBackgroundLoop запускает первичное сканирование и периодическое обновление каждые interval
func (p *ProxyPool) StartBackgroundLoop(interval time.Duration) {
	go func() {
		p.RunScan()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			p.RunScan()
		}
	}()
}

// TriggerAsyncScan запускает внеочередное сканирование, если оно ещё не идет
func (p *ProxyPool) TriggerAsyncScan() bool {
	p.mu.Lock()
	if p.scanInProgress {
		p.mu.Unlock()
		return false
	}
	p.mu.Unlock()
	go p.RunScan()
	return true
}

// AddCustomCandidates добавляет пользовательские адреса IP:Port в пул и запускает их проверку
func (p *ProxyPool) AddCustomCandidates(rawText string) int {
	parsed := parseRawLines(rawText, "http", "RU", "Custom")
	if len(parsed) == 0 {
		return 0
	}

	p.mu.Lock()
	p.customList = append(p.customList, parsed...)
	p.mu.Unlock()

	go func(items []CandidateProxy) {
		for _, item := range items {
			if res, ok := CheckCandidate(item); ok {
				p.upsertResult(*res)
			}
		}
	}(parsed)

	return len(parsed)
}

// RunScan выполняет полный цикл сбора и многопоточной проверки российских адресов
func (p *ProxyPool) RunScan() {
	p.mu.Lock()
	if p.scanInProgress {
		p.mu.Unlock()
		return
	}
	p.scanInProgress = true
	p.lastScanStarted = time.Now()
	customCopy := make([]CandidateProxy, len(p.customList))
	copy(customCopy, p.customList)

	for _, existing := range p.active {
		customCopy = append(customCopy, CandidateProxy{
			Address:  existing.Address,
			Protocol: existing.Protocol,
			Country:  existing.Country,
			Source:   existing.Source,
		})
	}
	p.mu.Unlock()

	log.Printf("[SCANNER] Начинаем сбор и гео-фильтрацию российских адресов...")
	candidates, rawTotal, foreignSkipped := FetchAllCandidates(customCopy, p.maxCandidates)

	p.mu.Lock()
	p.rawAnalyzed = rawTotal
	p.foreignFiltered = foreignSkipped
	p.totalCandidates = len(candidates)
	atomic.StoreInt64(&p.scannedCount, 0)
	p.mu.Unlock()

	scanStart := time.Now()
	jobs := make(chan CandidateProxy, len(candidates))
	var wg sync.WaitGroup

	for w := 0; w < p.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cand := range jobs {
				if res, ok := CheckCandidate(cand); ok {
					p.upsertResult(*res)
				} else {
					p.removeDead(cand.Protocol + "://" + cand.Address)
				}
				atomic.AddInt64(&p.scannedCount, 1)
			}
		}()
	}

	for _, c := range candidates {
		jobs <- c
	}
	close(jobs)
	wg.Wait()

	p.mu.Lock()
	p.scanInProgress = false
	p.lastScanEnded = time.Now()
	alive := len(p.active)
	p.mu.Unlock()

	log.Printf("[SCANNER] Цикл завершен за %v. Проверено RU-серверов: %d, Живых: %d",
		time.Since(scanStart).Round(time.Second), len(candidates), alive)
}

func (p *ProxyPool) upsertResult(res ProxyResult) {
	key := res.Protocol + "://" + res.Address
	p.mu.Lock()
	p.active[key] = res
	p.mu.Unlock()
}

func (p *ProxyPool) removeDead(key string) {
	p.mu.Lock()
	delete(p.active, key)
	p.mu.Unlock()
}

// GetProxies возвращает отфильтрованный и отсортированный список живых серверов РФ
func (p *ProxyPool) GetProxies(targetKey, protocol string, limit int) []ProxyResult {
	p.mu.RLock()
	list := make([]ProxyResult, 0, len(p.active))
	for _, item := range p.active {
		if protocol != "" && item.Protocol != protocol {
			continue
		}
		if targetKey != "" {
			if _, ok := item.Targets[targetKey]; !ok {
				continue
			}
		}
		list = append(list, item)
	}
	p.mu.RUnlock()

	sort.Slice(list, func(i, j int) bool {
		if targetKey != "" {
			return list[i].Targets[targetKey] < list[j].Targets[targetKey]
		}
		if list[i].DirectAccess != list[j].DirectAccess {
			return list[i].DirectAccess
		}
		if list[i].TargetCount != list[j].TargetCount {
			return list[i].TargetCount > list[j].TargetCount
		}
		return list[i].AvgLatencyMs < list[j].AvgLatencyMs
	})

	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	return list
}

// GetRandomProxy возвращает один случайный рабочий прокси из топ-25 самых быстрых
func (p *ProxyPool) GetRandomProxy(targetKey, protocol string) (*ProxyResult, bool) {
	candidates := p.GetProxies(targetKey, protocol, 25)
	if len(candidates) == 0 {
		return nil, false
	}
	idx := rand.Intn(len(candidates))
	chosen := candidates[idx]
	return &chosen, true
}

// GetStats формирует статистику пула
func (p *ProxyPool) GetStats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	byTarget := make(map[string]int)
	for _, t := range TargetList {
		byTarget[t.Key] = 0
	}

	directGov := 0
	for _, item := range p.active {
		if item.DirectAccess {
			directGov++
		}
		for k := range item.Targets {
			byTarget[k]++
		}
	}

	return PoolStats{
		RawAnalyzed:     p.rawAnalyzed,
		ForeignFiltered: p.foreignFiltered,
		TotalCandidates: p.totalCandidates,
		ScannedCount:    int(atomic.LoadInt64(&p.scannedCount)),
		AliveCount:      len(p.active),
		DirectGovCount:  directGov,
		ScanInProgress:  p.scanInProgress,
		LastScanStarted: p.lastScanStarted,
		LastScanEnded:   p.lastScanEnded,
		ByTarget:        byTarget,
		TargetsMeta:     TargetList,
	}
}
