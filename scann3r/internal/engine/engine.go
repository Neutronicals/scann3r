// Package engine implements the streaming pipeline orchestrator.
// It connects every component via Go channels so data flows in real time:
//
//   Spider ──[CrawlResult]──► Task Generator ──[FuzzTask]──► Fuzzer ──[FuzzResult]──► Analyzer ──[Finding]──► Storage
//
// URLs are piped to the fuzzer the exact millisecond they are discovered.
// No phase gates. No waiting. Pure streaming.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"sync"

	"github.com/venom-scanner/venom/internal/analyzer"
	"github.com/venom-scanner/venom/internal/config"
	"github.com/venom-scanner/venom/internal/crawler"
	"github.com/venom-scanner/venom/internal/models"
	"github.com/venom-scanner/venom/internal/netutil"
	"github.com/venom-scanner/venom/internal/scanner"
	"github.com/venom-scanner/venom/internal/scanner/payloads"
	"github.com/venom-scanner/venom/internal/storage"
	"github.com/venom-scanner/venom/internal/ui"
)

// Engine is the top‑level scan orchestrator.
type Engine struct {
	cfg *config.Config
	db  *storage.DB

	// Shared infrastructure
	client  *netutil.HTTPClient
	limiter *netutil.DomainRateLimiter

	// Pipeline components
	spider   *crawler.Spider
	sitemap  *crawler.SitemapParser
	fuzzer   *scanner.Fuzzer
	analyzer *analyzer.Analyzer

	// Real‑time statistics (shared across all goroutines)
	stats *models.ScanStats

	// Dashboard (optional — nil in headless mode)
	dashboard *ui.Dashboard

	// FindingCallback is called for every confirmed finding.
	// Used by the dashboard and for real‑time alerting.
	OnFinding func(*models.Finding)
}

// New creates a fully wired Engine. All components share the same HTTP client,
// rate limiter, and stats counters.
func New(cfg *config.Config, db *storage.DB) (*Engine, error) {
	stats := models.NewScanStats()

	client := netutil.NewHTTPClient(cfg)
	limiter := netutil.NewDomainRateLimiter(cfg.RatePerSec)

	// Load embedded payloads
	payloadMap, err := payloads.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("loading payloads: %w", err)
	}

	spider := crawler.NewSpider(cfg, client, limiter, stats)
	sitemapParser := crawler.NewSitemapParser(cfg, client, limiter)
	fuzzer := scanner.NewFuzzer(cfg, client, limiter, payloadMap, stats)
	analyzerInst := analyzer.NewAnalyzer(stats, 5)

	e := &Engine{
		cfg:      cfg,
		db:       db,
		client:   client,
		limiter:  limiter,
		spider:   spider,
		sitemap:  sitemapParser,
		fuzzer:   fuzzer,
		analyzer: analyzerInst,
		stats:    stats,
	}

	return e, nil
}

// Stats returns the live scan statistics.
func (e *Engine) Stats() *models.ScanStats {
	return e.stats
}

// SetDashboard attaches a TUI dashboard for real‑time display.
func (e *Engine) SetDashboard(d *ui.Dashboard) {
	e.dashboard = d
	e.OnFinding = func(f *models.Finding) {
		d.AddFinding(f)
	}
}

// Run executes the full streaming pipeline. It blocks until the scan is
// complete or the context is cancelled.
//
// The pipeline architecture:
//
//	                                ┌─────────────────┐
//	                                │  Sitemap Parser  │
//	                                └───────┬─────────┘
//	                                        │ (seeds frontier)
//	  ┌──────────┐   crawlResults    ┌──────┴──────┐   fuzzTasks    ┌─────────┐   fuzzResults   ┌──────────┐   findings   ┌─────────┐
//	  │  Spider   │ ───────────────► │   Task Gen   │ ────────────► │  Fuzzer  │ ──────────────► │ Analyzer │ ───────────► │ Storage │
//	  └──────────┘                   └─────────────┘                └─────────┘                 └──────────┘             └─────────┘
//
func (e *Engine) Run(ctx context.Context) error {
	e.stats.Status = "running"

	// Record scan in database
	cfgJSON, _ := json.Marshal(e.cfg)
	if err := e.db.CreateScan(ctx, e.cfg.ScanID, e.cfg.Target, cfgJSON); err != nil {
		return fmt.Errorf("creating scan record: %w", err)
	}

	e.logf("Starting scan against %s (ID: %s)", e.cfg.Target, e.cfg.ScanID)
	e.logf("Threads: crawl=%d fuzz=%d | Rate: %.0f req/s/domain | Depth: %d",
		e.cfg.CrawlThreads, e.cfg.FuzzThreads, e.cfg.RatePerSec, e.cfg.MaxDepth)

	// ─── Pipeline channels ───────────────────────────────────────────────
	// These are the arteries of the system. Data flows left to right
	// the instant it's produced. Buffered channels provide backpressure
	// without blocking the producers.
	crawlResults := make(chan *models.CrawlResult, 200)
	fuzzTasks := make(chan *models.FuzzTask, 500)
	fuzzResults := make(chan *models.FuzzResult, 500)
	findings := make(chan *models.Finding, 100)

	var wg sync.WaitGroup

	// ─── Stage 1: Discovery (Spider + Sitemap) ──────────────────────────
	// The spider crawls pages and pushes CrawlResults onto the channel
	// the instant each page is fetched and parsed.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(crawlResults)

		// Pre‑seed the frontier with sitemap/robots.txt discoveries
		sitemapURLs := e.sitemap.Discover(ctx)
		if len(sitemapURLs) > 0 {
			e.logf("Sitemap/robots.txt: discovered %d additional URLs", len(sitemapURLs))
		}

		// The spider crawls and streams results
		e.spider.Crawl(ctx, crawlResults)

		e.logf("Discovery phase complete: %d URLs found", e.stats.URLsFound.Load())
	}()

	// ─── Stage 2: Task Generator ────────────────────────────────────────
	// Reads CrawlResults and transforms them into FuzzTasks by extracting
	// parameters. This runs concurrently with the spider — the moment a
	// URL is crawled, its parameters are extracted and sent to the fuzzer.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(fuzzTasks)
		e.generateFuzzTasks(ctx, crawlResults, fuzzTasks)
	}()

	// ─── Stage 3: Fuzzer ────────────────────────────────────────────────
	// Reads FuzzTasks, generates mutated payloads, sends HTTP requests,
	// and pushes FuzzResults downstream. Runs N concurrent workers.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(fuzzResults)
		e.fuzzer.Fuzz(ctx, fuzzTasks, fuzzResults)
		e.logf("Fuzzing phase complete: %d requests sent", e.stats.RequestsSent.Load())
	}()

	// ─── Stage 4: Analyzer ──────────────────────────────────────────────
	// Reads FuzzResults and runs pattern + timing detection. Confirmed
	// vulnerabilities are pushed onto the findings channel.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(findings)
		e.analyzer.Analyze(ctx, fuzzResults, findings)
	}()

	// ─── Stage 5: Persistence ───────────────────────────────────────────
	// Reads findings and persists them to SQLite. Also notifies the
	// dashboard for real‑time display.
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.persistFindings(ctx, findings)
	}()

	// Wait for the entire pipeline to drain
	wg.Wait()

	// Finalise — use a fresh context because the original may be cancelled
	finalCtx := context.Background()

	if ctx.Err() != nil {
		// Scan was interrupted (Ctrl+C or timeout)
		e.stats.Status = "interrupted"
		e.logf("Scan interrupted — saving partial results...")
	} else {
		e.stats.Status = "completed"
	}

	if err := e.db.FinishScan(finalCtx, e.cfg.ScanID, e.stats); err != nil {
		e.logf("Warning: failed to finalize scan record: %v", err)
	}

	findingsMap := e.stats.GetFindings()
	totalFindings := int64(0)
	for _, c := range findingsMap {
		totalFindings += c
	}

	e.logf("Scan %s! %d findings across %d requests", e.stats.Status, totalFindings, e.stats.RequestsSent.Load())

	if e.dashboard != nil {
		e.dashboard.SetDone()
	}

	return nil
}

// ─── Stage 2 implementation ──────────────────────────────────────────────────

// generateFuzzTasks reads CrawlResults and produces FuzzTasks. It also
// persists endpoints and parameters to the database as a side effect.
func (e *Engine) generateFuzzTasks(ctx context.Context, results <-chan *models.CrawlResult, tasks chan<- *models.FuzzTask) {
	// Track parameter combinations we've already sent to avoid duplicates
	seen := make(map[string]bool)

	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-results:
			if !ok {
				return
			}

			// Persist endpoint to DB
			endpointID, err := e.db.InsertEndpoint(ctx, e.cfg.ScanID, result)
			if err != nil && e.cfg.Verbose {
				log.Printf("[engine] DB insert endpoint error: %v", err)
			}

			// Extract parameters from query strings
			queryParams := crawler.ExtractQueryParams(result.URL)
			for _, p := range queryParams {
				e.emitTask(ctx, seen, tasks, result, p, endpointID)
			}

			// Extract parameters from forms
			for _, form := range result.Forms {
				formParams := crawler.ExtractFormParams(form)
				for _, p := range formParams {
					task := &models.FuzzTask{
						URL:       form.Action,
						Method:    form.Method,
						Parameter: p,
						Endpoint:  result,
					}
					key := taskKey(task)
					if seen[key] {
						continue
					}
					seen[key] = true
					e.stats.ParametersFound.Add(1)

					// Persist parameter
					if endpointID > 0 {
						e.db.InsertParameter(ctx, endpointID, p)
					}

					select {
					case tasks <- task:
					case <-ctx.Done():
						return
					}
				}
			}

			// Also fuzz any JS‑discovered endpoints that have query params
			for _, jsURL := range result.JSEndpoints {
				jsParams := crawler.ExtractQueryParams(jsURL)
				for _, p := range jsParams {
					task := &models.FuzzTask{
						URL:       jsURL,
						Method:    "GET",
						Parameter: p,
						Endpoint:  result,
					}
					key := taskKey(task)
					if seen[key] {
						continue
					}
					seen[key] = true
					e.stats.ParametersFound.Add(1)

					select {
					case tasks <- task:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}
}

// emitTask creates and sends a FuzzTask for a query parameter.
func (e *Engine) emitTask(ctx context.Context, seen map[string]bool, tasks chan<- *models.FuzzTask,
	result *models.CrawlResult, param models.Parameter, endpointID int64) {

	task := &models.FuzzTask{
		URL:       result.URL,
		Method:    result.Method,
		Parameter: param,
		Endpoint:  result,
	}
	key := taskKey(task)
	if seen[key] {
		return
	}
	seen[key] = true
	e.stats.ParametersFound.Add(1)

	// Persist parameter
	if endpointID > 0 {
		e.db.InsertParameter(ctx, endpointID, param)
	}

	select {
	case tasks <- task:
	case <-ctx.Done():
	}
}

// ─── Stage 5 implementation ──────────────────────────────────────────────────

// persistFindings writes findings to SQLite and notifies the dashboard.
func (e *Engine) persistFindings(ctx context.Context, findings <-chan *models.Finding) {
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-findings:
			if !ok {
				return
			}

			f.ScanID = e.cfg.ScanID

			if err := e.db.InsertFinding(ctx, e.cfg.ScanID, f); err != nil {
				if e.cfg.Verbose {
					log.Printf("[engine] DB insert finding error: %v", err)
				}
				continue
			}

			// Notify dashboard
			if e.OnFinding != nil {
				e.OnFinding(f)
			}

			e.logf("🎯 [%s] %s in %s?%s via %s",
				severityLabel(f.Severity), f.Type, truncateURL(f.URL), f.Parameter, f.MutationStrategy)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func taskKey(t *models.FuzzTask) string {
	return t.URL + "|" + t.Method + "|" + t.Parameter.Name + "|" + t.Parameter.Location
}

func (e *Engine) logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if e.dashboard != nil {
		e.dashboard.AddLog(msg)
	}
	if e.cfg.Verbose {
		log.Println(msg)
	}
}

func truncateURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	path := u.Path
	if len(path) > 40 {
		path = path[:37] + "..."
	}
	return u.Host + path
}

func severityLabel(sev string) string {
	switch sev {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		return "INFO"
	}
}
