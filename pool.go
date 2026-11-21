package main

import (
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// PoolStats хранит сводную статистику сканера для API и веб-дашборда
type PoolStats struct {
	RawAnalyzed       int              `json:"raw_analyzed"`
	ForeignFiltered   int              `json:"foreign_filtered"`
	TotalCandidates   int              `json:"total_candidates"`
	ScannedCount      int              `json:"scanned_count"`
	AliveCount        int              `json:"alive_count"`
	HealthyCount      int              `json:"healthy_count"`
	DirectGovCount    int              `json:"direct_gov_count"`
	ScanInProgress    bool             `json:"scan_in_progress"`
	RecheckInProgress bool             `json:"recheck_in_progress"`
	LastScanStarted   time.Time        `json:"last_scan_started"`
	LastScanEnded     time.Time        `json:"last_scan_ended"`
	LastRecheckEnded  time.Time        `json:"last_recheck_ended"`
	SourcesCount      int              `json:"sources_count"`
	ByTarget          map[string]int   `json:"by_target"`
	TargetsMeta       []TargetResource `json:"targets_meta"`
	AdminEnabled      bool             `json:"admin_enabled"`
}

// ProxyPool управляет списком рабочих серверов и фоновыми проверками
type ProxyPool struct {
	cfg     Config
	checker *Checker
	geo     *geoResolver

	mu                sync.RWMutex
	active            map[string]ProxyResult // ключ: protocol://ip:port
	customList        []CandidateProxy
	customSeen        map[string]bool // адреса из customList (без протокола)
	customFails       map[string]int  // сколько полных сканов подряд адрес не прошёл
	rawAnalyzed       int
	foreignFiltered   int
	totalCandidates   int
	scannedCount      int64
	scanInProgress    bool
	recheckInProgress bool
	lastScanStarted   time.Time
	lastScanEnded     time.Time
	lastRecheckEnded  time.Time
	pending           map[string]bool // прокси, ожидающие внеочередной перепроверки (/api/report)
	geoTried          map[string]time.Time
	dirty             bool

	customRunning atomic.Bool
}

func NewProxyPool(cfg Config, checker *Checker, geo *geoResolver) *ProxyPool {
	return &ProxyPool{
		cfg:         cfg,
		checker:     checker,
		geo:         geo,
		active:      make(map[string]ProxyResult),
		customSeen:  make(map[string]bool),
		customFails: make(map[string]int),
		pending:     make(map[string]bool),
		geoTried:    make(map[string]time.Time),
	}
}

// Start запускает фоновые циклы до отмены ctx:
//   - сразу перепроверяет пул, загруженный с диска, затем делает полный скан;
//   - полный сбор из источников раз в FullScanEvery;
//   - перепроверка живых раз в RecheckEvery;
//   - неспешное дозаполнение городов (с учётом лимитов гео-API);
//   - периодическое сохранение пула на диск.
func (p *ProxyPool) Start(ctx context.Context) {
	go func() {
		if p.Count() > 0 {
			p.RecheckActive()
		}
		p.RunScan()
	}()

	go func() {
		full := time.NewTicker(p.cfg.FullScanEvery)
		recheck := time.NewTicker(p.cfg.RecheckEvery)
		geoTick := time.NewTicker(1600 * time.Millisecond)
		save := time.NewTicker(time.Minute)
		defer full.Stop()
		defer recheck.Stop()
		defer geoTick.Stop()
		defer save.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-full.C:
				go p.RunScan()
			case <-recheck.C:
				go p.RecheckActive()
			case <-geoTick.C:
				p.enrichOne()
			case <-save.C:
				p.SaveIfDirty()
			}
		}
	}()
}

func (p *ProxyPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.active)
}

// TriggerAsyncScan запускает внеочередное сканирование, если оно ещё не идет
func (p *ProxyPool) TriggerAsyncScan() bool {
	p.mu.RLock()
	busy := p.scanInProgress
	p.mu.RUnlock()
	if busy {
		return false
	}
	go p.RunScan()
	return true
}

// AddCustomCandidates принимает пользовательские адреса. Возвращает, сколько принято,
// и запущена ли проверка сразу (если предыдущая ещё идёт — адреса проверятся в ближайший скан).
func (p *ProxyPool) AddCustomCandidates(rawText string) (accepted int, checkingNow bool) {
	parsed := parseRawLines(rawText, "auto", "RU", "Custom")

	var fresh []CandidateProxy
	p.mu.Lock()
	for _, c := range parsed {
		if len(fresh) >= p.cfg.MaxAddPerCall {
			break
		}
		if !isAllowedProxyAddr(c.Address) || p.customSeen[c.Address] {
			continue
		}
		p.customSeen[c.Address] = true
		p.customList = append(p.customList, c)
		fresh = append(fresh, c)
	}
	// Ограничиваем размер: самые старые адреса вытесняются
	if over := len(p.customList) - p.cfg.MaxCustomList; over > 0 {
		for _, c := range p.customList[:over] {
			delete(p.customSeen, c.Address)
			delete(p.customFails, c.Address)
		}
		p.customList = append([]CandidateProxy(nil), p.customList[over:]...)
	}
	p.mu.Unlock()

	if len(fresh) == 0 {
		return 0, false
	}
	if !p.customRunning.CompareAndSwap(false, true) {
		return len(fresh), false
	}

	go func(items []CandidateProxy) {
		defer p.customRunning.Store(false)
		jobs := make(chan CandidateProxy)
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for c := range jobs {
					if res, ok := p.checker.CheckCandidate(c); ok {
						p.recordSuccess(*res)
					}
				}
			}()
		}
		for _, item := range items {
			for _, c := range expandProtocols(item) {
				jobs <- c
			}
		}
		close(jobs)
		wg.Wait()
	}(fresh)

	return len(fresh), true
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
	customCopy := make([]CandidateProxy, 0, len(p.customList)+len(p.active))
	customCopy = append(customCopy, p.customList...)
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
	candidates, rawTotal, foreignSkipped := FetchAllCandidates(customCopy, p.cfg.MaxCandidates)

	p.mu.Lock()
	p.rawAnalyzed = rawTotal
	p.foreignFiltered = foreignSkipped
	p.totalCandidates = len(candidates)
	atomic.StoreInt64(&p.scannedCount, 0)
	p.mu.Unlock()

	scanStart := time.Now()
	var okAddrs sync.Map
	p.runChecks(candidates, p.cfg.Workers, func(c CandidateProxy, ok bool) {
		if ok {
			okAddrs.Store(c.Address, true)
		}
		atomic.AddInt64(&p.scannedCount, 1)
	})

	p.mu.Lock()
	// Пользовательские адреса, которые не прошли MaxFails сканов подряд, забываем
	kept := p.customList[:0]
	for _, c := range p.customList {
		if _, ok := okAddrs.Load(c.Address); ok {
			p.customFails[c.Address] = 0
		} else {
			p.customFails[c.Address]++
		}
		if p.customFails[c.Address] >= p.cfg.MaxFails {
			delete(p.customFails, c.Address)
			delete(p.customSeen, c.Address)
			continue
		}
		kept = append(kept, c)
	}
	p.customList = kept
	p.scanInProgress = false
	p.lastScanEnded = time.Now()
	alive := len(p.active)
	p.mu.Unlock()

	p.SaveIfDirty()
	log.Printf("[SCANNER] Цикл завершен за %v. Проверено RU-кандидатов: %d, живых в пуле: %d",
		time.Since(scanStart).Round(time.Second), len(candidates), alive)
}

// RecheckActive перепроверяет только прокси, которые уже в пуле (быстро, без сбора из источников)
func (p *ProxyPool) RecheckActive() {
	p.mu.Lock()
	if p.recheckInProgress || p.scanInProgress { // полный скан и так проверяет активные
		p.mu.Unlock()
		return
	}
	p.recheckInProgress = true
	list := make([]CandidateProxy, 0, len(p.active))
	for _, r := range p.active {
		list = append(list, CandidateProxy{Address: r.Address, Protocol: r.Protocol, Country: r.Country, Source: r.Source})
	}
	p.mu.Unlock()

	workers := p.cfg.Workers
	if workers > 64 {
		workers = 64
	}
	p.runChecks(list, workers, nil)

	p.mu.Lock()
	p.recheckInProgress = false
	p.lastRecheckEnded = time.Now()
	p.mu.Unlock()
	p.SaveIfDirty()
}

func (p *ProxyPool) runChecks(list []CandidateProxy, workers int, done func(CandidateProxy, bool)) {
	jobs := make(chan CandidateProxy)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cand := range jobs {
				res, ok := p.checker.CheckCandidate(cand)
				if ok {
					p.recordSuccess(*res)
				} else {
					p.recordFailure(cand.Protocol + "://" + cand.Address)
				}
				if done != nil {
					done(cand, ok)
				}
			}
		}()
	}
	for _, c := range list {
		jobs <- c
	}
	close(jobs)
	wg.Wait()
}

// Report — сигнал от парсера, что прокси перестал работать. Прокси НЕ удаляется сразу
// (иначе любой мог бы «обнулить» пул ложными жалобами): он уходит вниз выдачи и
// внеочередно перепроверяется. Возвращает false, если такого прокси нет в пуле.
func (p *ProxyPool) Report(address, protocol string) bool {
	var keys []string
	p.mu.Lock()
	for _, proto := range []string{"http", "socks5"} {
		if protocol != "" && protocol != proto {
			continue
		}
		k := proto + "://" + address
		if r, ok := p.active[k]; ok && !p.pending[k] && len(p.pending) < 500 {
			p.pending[k] = true
			if r.ConsecutiveFails == 0 {
				r.ConsecutiveFails = 1 // временно понижаем в выдаче до результата перепроверки
				p.active[k] = r
			}
			keys = append(keys, k)
		}
	}
	found := len(keys) > 0
	if !found {
		for _, proto := range []string{"http", "socks5"} {
			if _, ok := p.active[proto+"://"+address]; ok {
				found = true // уже ждёт перепроверки
			}
		}
	}
	p.mu.Unlock()

	for _, k := range keys {
		r := p.get(k)
		go func(k string, c CandidateProxy) {
			defer func() { p.mu.Lock(); delete(p.pending, k); p.mu.Unlock() }()
			if res, ok := p.checker.CheckCandidate(c); ok {
				p.recordSuccess(*res)
			} else {
				p.recordFailure(k)
			}
		}(k, CandidateProxy{Address: r.Address, Protocol: r.Protocol, Country: r.Country, Source: r.Source})
	}
	return found
}

func (p *ProxyPool) get(key string) ProxyResult {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.active[key]
}

func (p *ProxyPool) recordSuccess(res ProxyResult) {
	key := res.key()
	p.mu.Lock()
	defer p.mu.Unlock()
	if prev, ok := p.active[key]; ok {
		res.FirstSeenAt = prev.FirstSeenAt
		res.TotalChecks = prev.TotalChecks
		res.TotalSuccess = prev.TotalSuccess
		if prev.ExitIP == res.ExitIP {
			res.City, res.Region, res.ISP = prev.City, prev.Region, prev.ISP
		}
		if res.Source == "" || res.Source == "Custom" {
			if prev.Source != "" {
				res.Source = prev.Source
			}
		}
	} else {
		res.FirstSeenAt = time.Now()
	}
	if res.City == "" {
		if info, ok := p.geo.Cached(geoIPOf(res)); ok {
			res.City, res.Region, res.ISP = info.City, info.Region, info.ISP
		}
	}
	res.TotalChecks++
	res.TotalSuccess++
	res.ConsecutiveFails = 0
	res.recomputeUptime()
	p.active[key] = res
	p.dirty = true
}

func (p *ProxyPool) recordFailure(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.active[key]
	if !ok {
		return
	}
	r.TotalChecks++
	r.ConsecutiveFails++
	r.LastCheckedAt = time.Now()
	r.recomputeUptime()
	if r.ConsecutiveFails >= p.cfg.MaxFails {
		delete(p.active, key)
	} else {
		p.active[key] = r
	}
	p.dirty = true
}

func geoIPOf(r ProxyResult) string {
	if r.ExitIP != "" {
		return r.ExitIP
	}
	host, _, _ := net.SplitHostPort(r.Address)
	return host
}

// enrichOne дозаполняет город/провайдера для одного прокси за вызов (≈40 запросов/мин)
func (p *ProxyPool) enrichOne() {
	var key, ip string
	now := time.Now()
	p.mu.Lock()
	for k, r := range p.active {
		if r.City != "" {
			continue
		}
		cand := geoIPOf(r)
		if t, ok := p.geoTried[cand]; ok && now.Sub(t) < 30*time.Minute {
			continue
		}
		key, ip = k, cand
		break
	}
	if ip != "" {
		p.geoTried[ip] = now
	}
	if len(p.geoTried) > 20000 {
		p.geoTried = make(map[string]time.Time)
	}
	p.mu.Unlock()
	if ip == "" {
		return
	}

	info, ok := p.geo.Lookup(ip)
	if !ok {
		p.mu.Lock()
		delete(p.geoTried, ip) // лимит API — попробуем этот IP снова позже
		p.mu.Unlock()
		return
	}
	p.mu.Lock()
	if r, ok := p.active[key]; ok && geoIPOf(r) == ip {
		r.City, r.Region, r.ISP = info.City, info.Region, info.ISP
		if r.City == "" {
			r.City = "Россия"
		}
		p.active[key] = r
		p.dirty = true
	}
	p.mu.Unlock()
}

// GetProxies возвращает отфильтрованный и отсортированный список живых серверов.
// Прокси с 2+ провалами подряд в выдачу не попадают (они ждут подтверждения или удаления).
func (p *ProxyPool) GetProxies(targetKey, protocol string, limit int) []ProxyResult {
	p.mu.RLock()
	list := make([]ProxyResult, 0, len(p.active))
	for _, item := range p.active {
		if item.ConsecutiveFails >= 2 {
			continue
		}
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

	uptimeBucket := func(r ProxyResult) int { return int(r.UptimePercent / 10) }
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.ConsecutiveFails != b.ConsecutiveFails {
			return a.ConsecutiveFails < b.ConsecutiveFails
		}
		if targetKey != "" {
			if uptimeBucket(a) != uptimeBucket(b) {
				return uptimeBucket(a) > uptimeBucket(b)
			}
			return a.Targets[targetKey] < b.Targets[targetKey]
		}
		if a.DirectAccess != b.DirectAccess {
			return a.DirectAccess
		}
		if a.TargetCount != b.TargetCount {
			return a.TargetCount > b.TargetCount
		}
		if uptimeBucket(a) != uptimeBucket(b) {
			return uptimeBucket(a) > uptimeBucket(b)
		}
		return a.AvgLatencyMs < b.AvgLatencyMs
	})

	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	return list
}

// GetRandomProxy возвращает случайный прокси из топ-25, предпочитая полностью «здоровые»
func (p *ProxyPool) GetRandomProxy(targetKey, protocol string) (*ProxyResult, bool) {
	all := p.GetProxies(targetKey, protocol, 0)
	healthy := make([]ProxyResult, 0, 25)
	for _, r := range all {
		if r.ConsecutiveFails == 0 {
			healthy = append(healthy, r)
			if len(healthy) == 25 {
				break
			}
		}
	}
	if len(healthy) == 0 {
		if len(all) == 0 {
			return nil, false
		}
		healthy = all
		if len(healthy) > 25 {
			healthy = healthy[:25]
		}
	}
	chosen := healthy[rand.Intn(len(healthy))]
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
	directGov, healthy := 0, 0
	for _, item := range p.active {
		if item.ConsecutiveFails >= 2 {
			continue
		}
		if item.ConsecutiveFails == 0 {
			healthy++
		}
		if item.DirectAccess {
			directGov++
		}
		for k := range item.Targets {
			byTarget[k]++
		}
	}

	return PoolStats{
		RawAnalyzed:       p.rawAnalyzed,
		ForeignFiltered:   p.foreignFiltered,
		TotalCandidates:   p.totalCandidates,
		ScannedCount:      int(atomic.LoadInt64(&p.scannedCount)),
		AliveCount:        len(p.active),
		HealthyCount:      healthy,
		DirectGovCount:    directGov,
		ScanInProgress:    p.scanInProgress,
		RecheckInProgress: p.recheckInProgress,
		LastScanStarted:   p.lastScanStarted,
		LastScanEnded:     p.lastScanEnded,
		LastRecheckEnded:  p.lastRecheckEnded,
		SourcesCount:      len(defaultSources),
		ByTarget:          byTarget,
		TargetsMeta:       TargetList,
		AdminEnabled:      p.cfg.AdminToken != "",
	}
}

// ---------- Сохранение пула на диск ----------

type poolSnapshot struct {
	Version int           `json:"version"`
	SavedAt time.Time     `json:"saved_at"`
	Proxies []ProxyResult `json:"proxies"`
}

// SaveIfDirty атомарно записывает пул в DATA_FILE (через временный файл + rename, права 0600)
func (p *ProxyPool) SaveIfDirty() {
	if p.cfg.DataFile == "" {
		return
	}
	p.mu.Lock()
	if !p.dirty {
		p.mu.Unlock()
		return
	}
	snap := poolSnapshot{Version: 1, SavedAt: time.Now(), Proxies: make([]ProxyResult, 0, len(p.active))}
	for _, r := range p.active {
		snap.Proxies = append(snap.Proxies, r)
	}
	p.dirty = false
	p.mu.Unlock()

	if err := writeFileAtomic(p.cfg.DataFile, snap); err != nil {
		log.Printf("[STORAGE] Не удалось сохранить пул: %v", err)
		p.mu.Lock()
		p.dirty = true
		p.mu.Unlock()
	}
}

func writeFileAtomic(path string, v interface{}) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".pool-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := json.NewEncoder(tmp).Encode(v); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Load читает сохранённый пул. Файл считается недоверенным: каждая запись проверяется,
// а все загруженные прокси помечаются как требующие перепроверки.
func (p *ProxyPool) Load() int {
	if p.cfg.DataFile == "" {
		return 0
	}
	f, err := os.Open(p.cfg.DataFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[STORAGE] Не удалось открыть %s: %v", p.cfg.DataFile, err)
		}
		return 0
	}
	defer f.Close()
	var snap poolSnapshot
	if err := json.NewDecoder(f).Decode(&snap); err != nil {
		log.Printf("[STORAGE] Файл пула повреждён, игнорирую: %v", err)
		return 0
	}
	if time.Since(snap.SavedAt) > 72*time.Hour {
		log.Printf("[STORAGE] Сохранённый пул старше 72 часов, игнорирую")
		return 0
	}

	n := 0
	p.mu.Lock()
	for _, r := range snap.Proxies {
		if (r.Protocol != "http" && r.Protocol != "socks5") || !isAllowedProxyAddr(r.Address) {
			continue
		}
		if r.Targets == nil {
			r.Targets = map[string]int64{}
		}
		r.ConsecutiveFails = 1 // в выдаче, но ниже свежепроверенных — до первой перепроверки
		p.active[r.key()] = r
		n++
	}
	p.mu.Unlock()
	log.Printf("[STORAGE] Загружено %d прокси из %s (будут перепроверены)", n, p.cfg.DataFile)
	return n
}
