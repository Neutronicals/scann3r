// Package crawler implements the intelligent web spider that discovers
// endpoints, forms, JS files, and API routes. It streams results onto a
// channel the instant they are found — no waiting for a full crawl to finish.
package crawler

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/venom-scanner/venom/internal/config"
	"github.com/venom-scanner/venom/internal/models"
	"github.com/venom-scanner/venom/internal/netutil"
)

// Spider crawls a target website and emits CrawlResults on a channel.
type Spider struct {
	cfg     *config.Config
	client  *netutil.HTTPClient
	limiter *netutil.DomainRateLimiter
	stats   *models.ScanStats

	// Deduplication: tracks URLs we've already queued.
	visited sync.Map // map[string]bool

	// Internal work queue.
	frontier chan crawlItem
}

// crawlItem is an internal work‑queue entry (not exported).
type crawlItem struct {
	url       string
	depth     int
	parentURL string
	source    string
}

// NewSpider creates a new Spider.
func NewSpider(cfg *config.Config, client *netutil.HTTPClient, limiter *netutil.DomainRateLimiter, stats *models.ScanStats) *Spider {
	return &Spider{
		cfg:      cfg,
		client:   client,
		limiter:  limiter,
		stats:    stats,
		frontier: make(chan crawlItem, 5000), // large buffer to avoid blocking producers
	}
}

// Crawl starts the spider. Discovered pages are sent on `results` the
// moment they are processed. Crawl blocks until the frontier is exhausted
// or the context is cancelled — the caller should close `results` after
// Crawl returns.
func (s *Spider) Crawl(ctx context.Context, results chan<- *models.CrawlResult) {
	// Seed the frontier
	s.enqueue(s.cfg.Target, 0, "", "seed")

	var wg sync.WaitGroup

	// Spawn N crawler workers
	for i := 0; i < s.cfg.CrawlThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, results)
		}()
	}

	// Wait for all workers to drain the frontier, then signal done.
	// We use a separate goroutine to close the frontier channel once
	// no new items have arrived for a while (indicating exhaustion).
	go func() {
		wg.Wait()
	}()

	wg.Wait()
}

// enqueue adds a URL to the frontier if it hasn't been visited and is in scope.
func (s *Spider) enqueue(rawURL string, depth int, parentURL, source string) {
	// Normalise
	rawURL = normalizeURL(rawURL)
	if rawURL == "" {
		return
	}

	// Scope check
	if !s.cfg.InScope(rawURL) {
		return
	}

	// Depth check
	if depth > s.cfg.MaxDepth {
		return
	}

	// Dedup
	if _, loaded := s.visited.LoadOrStore(rawURL, true); loaded {
		return
	}

	// Non‑blocking send; if the frontier is full we drop the URL
	// rather than blocking a worker.
	select {
	case s.frontier <- crawlItem{url: rawURL, depth: depth, parentURL: parentURL, source: source}:
	default:
		if s.cfg.Verbose {
			log.Printf("[spider] frontier full, dropping %s", rawURL)
		}
	}
}

// worker is a long‑running goroutine that pulls items from the frontier,
// fetches them, extracts data, and pushes results onto the output channel.
func (s *Spider) worker(ctx context.Context, results chan<- *models.CrawlResult) {
	// The worker exits when it hasn't received work for 3 seconds,
	// meaning the frontier is likely exhausted.
	idleTimeout := 3 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case item, ok := <-s.frontier:
			if !ok {
				return
			}
			s.processItem(ctx, item, results)
		case <-time.After(idleTimeout):
			// No work for 3 seconds — assume the crawl is done.
			return
		}
	}
}

// processItem fetches a single URL, extracts links/forms/scripts, and
// sends the result downstream.
func (s *Spider) processItem(ctx context.Context, item crawlItem, results chan<- *models.CrawlResult) {
	// Rate limit
	if err := s.limiter.Wait(ctx, item.url); err != nil {
		return
	}

	resp, body, err := s.client.Get(ctx, item.url)
	if err != nil {
		s.stats.Errors.Add(1)
		if s.cfg.Verbose {
			log.Printf("[spider] error fetching %s: %v", item.url, err)
		}
		return
	}
	s.stats.RequestsSent.Add(1)

	// Handle WAF / rate‑limit responses
	if resp.StatusCode == http.StatusTooManyRequests {
		s.limiter.BackOff(item.url)
		s.stats.WAFBlocks.Add(1)
		return
	}

	contentType := resp.Header.Get("Content-Type")

	result := &models.CrawlResult{
		URL:          item.url,
		Method:       "GET",
		StatusCode:   resp.StatusCode,
		Headers:      resp.Header,
		Body:         body,
		ContentType:  contentType,
		Depth:        item.depth,
		ParentURL:    item.parentURL,
		Source:       item.source,
		DiscoveredAt: time.Now(),
	}

	// Only parse HTML pages for links/forms/scripts
	if strings.Contains(contentType, "text/html") {
		s.extractHTML(item, body, result)
	}

	// If it's a JS file, mine endpoints from it
	if strings.Contains(contentType, "javascript") || strings.HasSuffix(item.url, ".js") {
		endpoints := ExtractJSEndpoints(string(body))
		for _, ep := range endpoints {
			resolved := resolveURL(item.url, ep)
			if resolved != "" {
				result.JSEndpoints = append(result.JSEndpoints, resolved)
				s.enqueue(resolved, item.depth+1, item.url, "js_parse")
			}
		}
		s.stats.JSFilesFound.Add(1)
	}

	s.stats.URLsFound.Add(1)

	// Push result downstream immediately
	select {
	case results <- result:
	case <-ctx.Done():
	}
}

// extractHTML parses an HTML page and populates the CrawlResult with
// links, forms, and script sources.
func (s *Spider) extractHTML(item crawlItem, body []byte, result *models.CrawlResult) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	// --- Links ---
	doc.Find("a[href]").Each(func(_ int, sel *goquery.Selection) {
		href, exists := sel.Attr("href")
		if !exists || href == "" {
			return
		}
		abs := resolveURL(item.url, href)
		if abs != "" {
			result.Links = append(result.Links, abs)
			s.enqueue(abs, item.depth+1, item.url, "crawl")
		}
	})

	// --- Script sources ---
	doc.Find("script[src]").Each(func(_ int, sel *goquery.Selection) {
		src, exists := sel.Attr("src")
		if !exists || src == "" {
			return
		}
		abs := resolveURL(item.url, src)
		if abs != "" {
			result.Scripts = append(result.Scripts, abs)
			s.enqueue(abs, item.depth+1, item.url, "crawl")
		}
	})

	// --- Inline scripts: mine for endpoints ---
	doc.Find("script:not([src])").Each(func(_ int, sel *goquery.Selection) {
		code := sel.Text()
		if code == "" {
			return
		}
		endpoints := ExtractJSEndpoints(code)
		for _, ep := range endpoints {
			resolved := resolveURL(item.url, ep)
			if resolved != "" {
				result.JSEndpoints = append(result.JSEndpoints, resolved)
				s.enqueue(resolved, item.depth+1, item.url, "js_parse")
			}
		}
	})

	// --- Forms ---
	forms := ExtractForms(doc, item.url)
	result.Forms = forms
	s.stats.FormsFound.Add(int64(len(forms)))

	// Enqueue form action URLs
	for _, f := range forms {
		if f.Action != "" {
			s.enqueue(f.Action, item.depth+1, item.url, "form")
		}
	}
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

// resolveURL resolves a potentially relative URL against a base.
func resolveURL(base, ref string) string {
	// Skip fragments, mailto, tel, javascript, data URIs
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "mailto:") ||
		strings.HasPrefix(ref, "tel:") || strings.HasPrefix(ref, "javascript:") ||
		strings.HasPrefix(ref, "data:") {
		return ""
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	resolved := baseURL.ResolveReference(refURL)
	// Strip fragment
	resolved.Fragment = ""
	return resolved.String()
}

// normalizeURL strips fragments, trailing slashes, and lowercases the scheme/host.
func normalizeURL(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	u.Fragment = ""
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	result := u.String()
	// Remove trailing slash for consistency (except for root)
	if result != fmt.Sprintf("%s://%s/", u.Scheme, u.Host) {
		result = strings.TrimRight(result, "/")
	}
	return result
}
