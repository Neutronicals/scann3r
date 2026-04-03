package scanner

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/venom-scanner/venom/internal/config"
	"github.com/venom-scanner/venom/internal/models"
	"github.com/venom-scanner/venom/internal/netutil"
)

// Fuzzer reads FuzzTasks from its input channel, generates mutated payloads,
// sends them, and writes FuzzResults to its output channel — all in real time.
type Fuzzer struct {
	cfg     *config.Config
	client  *netutil.HTTPClient
	limiter *netutil.DomainRateLimiter
	mutator *Mutator
	stats   *models.ScanStats

	// All loaded payload templates keyed by category (sqli, xss, etc.)
	payloads map[string]*models.PayloadFile

	// Track which mutation strategies succeed on this target so we can
	// prioritise them for future tasks.
	successfulMutations sync.Map // map[string]int (strategy name → hit count)
}

// NewFuzzer creates a Fuzzer wired to the shared HTTP client and rate limiter.
func NewFuzzer(
	cfg *config.Config,
	client *netutil.HTTPClient,
	limiter *netutil.DomainRateLimiter,
	payloads map[string]*models.PayloadFile,
	stats *models.ScanStats,
) *Fuzzer {
	return &Fuzzer{
		cfg:      cfg,
		client:   client,
		limiter:  limiter,
		mutator:  NewMutator(),
		payloads: payloads,
		stats:    stats,
	}
}

// Fuzz reads tasks from `tasks`, processes them concurrently, and writes
// results to `results`. It blocks until the tasks channel is closed and all
// workers have drained, then returns.
func (f *Fuzzer) Fuzz(ctx context.Context, tasks <-chan *models.FuzzTask, results chan<- *models.FuzzResult) {
	var wg sync.WaitGroup

	for i := 0; i < f.cfg.FuzzThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.worker(ctx, tasks, results)
		}()
	}

	wg.Wait()
}

// worker is a single fuzzer goroutine.
func (f *Fuzzer) worker(ctx context.Context, tasks <-chan *models.FuzzTask, results chan<- *models.FuzzResult) {
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-tasks:
			if !ok {
				return // channel closed
			}
			f.processTask(ctx, task, results)
		}
	}
}

// processTask runs all relevant payloads (and their mutations) against a single
// parameter on a single endpoint.
func (f *Fuzzer) processTask(ctx context.Context, task *models.FuzzTask, results chan<- *models.FuzzResult) {
	for _, pf := range f.payloads {
		for _, entry := range pf.Payloads {
			// Generate mutated variants of this payload
			mutated := f.mutator.MutateRandom(entry.Value, 5) // original + 5 mutations

			for _, mp := range mutated {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Count this as a pending request
				f.stats.RequestsTotal.Add(1)

				// Rate‑limit before sending
				if err := f.limiter.Wait(ctx, task.URL); err != nil {
					return
				}

				result := f.sendPayload(ctx, task, mp.Value, mp.Strategy)
				f.stats.RequestsSent.Add(1)

				if result.Error != nil {
					f.stats.Errors.Add(1)
					if f.cfg.Verbose {
						log.Printf("[fuzzer] error: %v", result.Error)
					}
					continue
				}

				// Detect WAF block (403 or challenge pages)
				if result.StatusCode == http.StatusForbidden ||
					result.StatusCode == http.StatusTooManyRequests {
					f.stats.WAFBlocks.Add(1)
					if result.StatusCode == http.StatusTooManyRequests {
						f.limiter.BackOff(task.URL)
					}
				}

				// Push result downstream for analysis
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// sendPayload constructs and sends a single HTTP request with the payload
// injected into the target parameter.
func (f *Fuzzer) sendPayload(ctx context.Context, task *models.FuzzTask, payload, mutation string) *models.FuzzResult {
	result := &models.FuzzResult{
		Task:         task,
		Payload:      payload,
		MutationName: mutation,
	}

	var req *http.Request
	var err error

	switch task.Parameter.Location {
	case "query":
		req, err = f.buildQueryRequest(ctx, task, payload)
	case "body":
		req, err = f.buildBodyRequest(ctx, task, payload)
	default:
		req, err = f.buildQueryRequest(ctx, task, payload) // fallback
	}

	if err != nil {
		result.Error = fmt.Errorf("building request: %w", err)
		return result
	}

	start := time.Now()
	resp, body, err := f.client.Do(ctx, req)
	result.ResponseTime = time.Since(start)

	if err != nil {
		result.Error = err
		return result
	}

	result.StatusCode = resp.StatusCode
	result.ResponseBody = body
	result.ContentLength = int64(len(body))
	result.ResponseHeaders = resp.Header

	return result
}

// buildQueryRequest creates a GET request with the payload in a query parameter.
func (f *Fuzzer) buildQueryRequest(ctx context.Context, task *models.FuzzTask, payload string) (*http.Request, error) {
	u, err := url.Parse(task.URL)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set(task.Parameter.Name, payload)
	u.RawQuery = q.Encode()

	return http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
}

// buildBodyRequest creates a POST request with the payload in the form body.
func (f *Fuzzer) buildBodyRequest(ctx context.Context, task *models.FuzzTask, payload string) (*http.Request, error) {
	// Build form data with the injected parameter
	form := url.Values{}
	form.Set(task.Parameter.Name, payload)

	// If the original endpoint had other form fields, include them with
	// their default values so the request looks more legitimate.
	if task.Endpoint != nil {
		for _, fd := range task.Endpoint.Forms {
			for _, inp := range fd.Inputs {
				if inp.Name != "" && inp.Name != task.Parameter.Name {
					form.Set(inp.Name, inp.Value)
				}
			}
		}
	}

	method := task.Method
	if method == "" {
		method = http.MethodPost
	}

	body := strings.NewReader(form.Encode())
	req, err := http.NewRequestWithContext(ctx, method, task.URL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// RecordSuccess is called when the analyzer confirms a finding, so the
// fuzzer learns which mutation strategies work against this target.
func (f *Fuzzer) RecordSuccess(strategy string) {
	val, _ := f.successfulMutations.LoadOrStore(strategy, 0)
	count := val.(int) + 1
	f.successfulMutations.Store(strategy, count)
}
