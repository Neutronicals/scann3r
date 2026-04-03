// Package config defines the central configuration for a Venom scan.
package config

import (
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
)

// Config holds every tunable knob for a scan run.
type Config struct {
	// Target
	Target string   // seed URL (e.g. https://example.com)
	Scope  []string // allowed hostnames; auto‑populated from Target if empty

	// Crawling
	MaxDepth     int           // link‑follow depth (default 3)
	CrawlThreads int           // concurrent crawler goroutines (default 20)
	RespectRobots bool          // honour robots.txt disallow rules (default true)

	// Fuzzing
	FuzzThreads int // concurrent fuzzer goroutines (default 30)

	// Rate limiting
	RatePerSec float64 // max requests/sec per domain (default 10)

	// Networking
	Timeout   time.Duration // per‑request timeout (default 10s)

	// Output
	OutputFile   string // report file path (default: stdout)
	OutputFormat string // json | html | md (default json)

	// Storage
	DBPath string // SQLite database path (default venom.db)

	// Runtime
	ScanID  string // unique ID for this run
	Verbose bool

	// User‑Agent pool for fingerprint rotation
	UserAgents []string
}

// DefaultConfig returns sane defaults suitable for a single laptop.
func DefaultConfig() *Config {
	return &Config{
		MaxDepth:      3,
		CrawlThreads:  20,
		FuzzThreads:   30,
		RatePerSec:    10.0,
		Timeout:       10 * time.Second,
		OutputFormat:  "json",
		DBPath:        "scann3r.db",
		RespectRobots: true,
		ScanID:        uuid.New().String(),
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
			"Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
		},
	}
}

// Validate checks required fields and fills in computed defaults.
func (c *Config) Validate() error {
	if c.Target == "" {
		return fmt.Errorf("target URL is required")
	}

	u, err := url.Parse(c.Target)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("target URL must include scheme and host (got %q)", c.Target)
	}

	// Auto‑scope to target host if the user didn't provide explicit scope.
	if len(c.Scope) == 0 {
		c.Scope = []string{u.Host}
	}

	if c.MaxDepth < 1 {
		c.MaxDepth = 1
	}
	if c.CrawlThreads < 1 {
		c.CrawlThreads = 1
	}
	if c.FuzzThreads < 1 {
		c.FuzzThreads = 1
	}
	if c.RatePerSec <= 0 {
		c.RatePerSec = 1
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.ScanID == "" {
		c.ScanID = uuid.New().String()
	}
	return nil
}

// InScope returns true if the given URL's host is within the allowed scope.
func (c *Config) InScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	for _, allowed := range c.Scope {
		if u.Host == allowed {
			return true
		}
	}
	return false
}
