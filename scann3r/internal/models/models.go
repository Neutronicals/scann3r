// Package models defines all shared data structures used across the Venom scanner pipeline.
// Every channel in the streaming architecture carries one of these types.
package models

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Discovery types (produced by the crawler, consumed by the engine)
// ---------------------------------------------------------------------------

// CrawlResult represents a single discovered page and all data extracted from it.
type CrawlResult struct {
	URL          string
	Method       string
	StatusCode   int
	Headers      http.Header
	Body         []byte
	ContentType  string
	Links        []string    // outgoing URLs found on the page
	Forms        []FormData  // extracted HTML forms
	Scripts      []string    // JS file URLs found in <script src="...">
	JSEndpoints  []string    // API‑like endpoints mined from inline/external JS
	Depth        int         // how many hops from the seed URL
	ParentURL    string      // the page that linked to this one
	Source       string      // "crawl", "js_parse", "sitemap", "form"
	DiscoveredAt time.Time
}

// FormData represents an HTML <form> and its inputs.
type FormData struct {
	Action  string       // form action URL (resolved to absolute)
	Method  string       // GET or POST
	Enctype string       // encoding type
	Inputs  []InputField // all <input>, <select>, <textarea>
	FormURL string       // the page where the form was found
}

// InputField represents a single form field.
type InputField struct {
	Name  string
	Type  string // text, hidden, password, email, etc.
	Value string // default/pre‑filled value
}

// ---------------------------------------------------------------------------
// Scanning types (produced by the engine/fuzzer, consumed by the analyzer)
// ---------------------------------------------------------------------------

// Parameter represents a user‑controllable input discovered on an endpoint.
type Parameter struct {
	Name     string
	Value    string
	Location string // "query", "body", "header", "cookie", "path"
}

// FuzzTask is a single unit of work for the fuzzer: "inject payloads into
// this parameter on this endpoint."
type FuzzTask struct {
	URL       string
	Method    string
	Parameter Parameter
	Endpoint  *CrawlResult // the original crawl result for context
}

// FuzzResult is the outcome of sending one mutated payload.
type FuzzResult struct {
	Task           *FuzzTask
	Payload        string
	MutationName   string
	ResponseBody   []byte
	ResponseTime   time.Duration
	StatusCode     int
	ContentLength  int64
	ResponseHeaders http.Header
	Error          error
}

// ---------------------------------------------------------------------------
// Analysis types (produced by the analyzer, consumed by storage)
// ---------------------------------------------------------------------------

// Finding represents a confirmed or suspected vulnerability.
type Finding struct {
	ID                string
	ScanID            string
	URL               string
	Method            string
	Parameter         string
	ParameterLocation string
	Type              string  // sqli, xss, cmdi, ssrf, lfi, ssti, openredirect
	Severity          string  // critical, high, medium, low, info
	Payload           string
	MutationStrategy  string
	Evidence          string  // snippet from the response proving the finding
	Confidence        float64 // 0.0 – 1.0
	FoundAt           time.Time
}

// ---------------------------------------------------------------------------
// Payload template types (loaded from embedded YAML)
// ---------------------------------------------------------------------------

// PayloadFile is the top‑level structure of a payload YAML file.
type PayloadFile struct {
	Name       string         `yaml:"name"`
	Category   string         `yaml:"category"`
	Severity   string         `yaml:"severity"`
	Payloads   []PayloadEntry `yaml:"payloads"`
	Indicators []string       `yaml:"indicators"`
}

// PayloadEntry is a single payload value with its detection approach.
type PayloadEntry struct {
	Value     string `yaml:"value"`
	Detection string `yaml:"detection"` // error_based, union_based, reflected, blind, time_based
}

// ---------------------------------------------------------------------------
// Real‑time statistics (thread‑safe, updated by every pipeline stage)
// ---------------------------------------------------------------------------

// ScanStats tracks live scan metrics. All counters are atomic so every
// goroutine in the pipeline can safely increment them.
type ScanStats struct {
	URLsFound       atomic.Int64
	JSFilesFound    atomic.Int64
	FormsFound      atomic.Int64
	ParametersFound atomic.Int64
	RequestsSent    atomic.Int64
	RequestsTotal   atomic.Int64
	Errors          atomic.Int64
	WAFBlocks       atomic.Int64

	// Findings counters keyed by severity
	mu       sync.Mutex
	Findings map[string]int64

	Status    string
	Progress  float64
	StartedAt time.Time
}

// NewScanStats creates a zeroed ScanStats.
func NewScanStats() *ScanStats {
	return &ScanStats{
		Findings:  make(map[string]int64),
		StartedAt: time.Now(),
		Status:    "initializing",
	}
}

// AddFinding thread‑safely increments the count for a severity level.
func (s *ScanStats) AddFinding(severity string) {
	s.mu.Lock()
	s.Findings[severity]++
	s.mu.Unlock()
}

// GetFindings returns a snapshot copy of the findings map.
func (s *ScanStats) GetFindings() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make(map[string]int64, len(s.Findings))
	for k, v := range s.Findings {
		cp[k] = v
	}
	return cp
}

// RequestRate returns the average requests per second since the scan started.
func (s *ScanStats) RequestRate() float64 {
	elapsed := time.Since(s.StartedAt).Seconds()
	if elapsed == 0 {
		return 0
	}
	return float64(s.RequestsSent.Load()) / elapsed
}
