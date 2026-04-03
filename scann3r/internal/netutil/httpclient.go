// Package netutil provides the shared HTTP client and fingerprint rotation
// used by every stage of the Venom pipeline.
package netutil

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/venom-scanner/venom/internal/config"
)

const (
	maxResponseBody = 256 * 1024 // 256 KB cap per response to protect RAM
	maxRedirects    = 10
)

// HTTPClient wraps http.Client with fingerprint rotation, retries,
// configurable timeouts, and a response‑body size cap.
type HTTPClient struct {
	client     *http.Client
	userAgents []string
	mu         sync.Mutex
	rng        *rand.Rand
	verbose    bool
}

// NewHTTPClient builds a production‑grade HTTP client.
func NewHTTPClient(cfg *config.Config) *HTTPClient {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // pentesting – targets may have self‑signed certs
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout + 5*time.Second, // overall deadline slightly beyond header timeout
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}

	return &HTTPClient{
		client:     client,
		userAgents: cfg.UserAgents,
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
		verbose:    cfg.Verbose,
	}
}

// Do sends an HTTP request with a rotated User‑Agent and up to 3 retries
// on transient failures. The returned body is capped at maxResponseBody bytes.
func (h *HTTPClient) Do(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
	// Rotate fingerprint
	req.Header.Set("User-Agent", h.randomUA())
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	req = req.WithContext(ctx)

	var (
		resp *http.Response
		err  error
	)

	// Retry loop with exponential back‑off (max 3 attempts)
	for attempt := 0; attempt < 3; attempt++ {
		resp, err = h.client.Do(req)
		if err == nil {
			break
		}
		// Don't retry on context cancellation
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		backoff := time.Duration(1<<uint(attempt)) * 200 * time.Millisecond
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("request failed after 3 attempts: %w", err)
	}

	// Read body with size cap
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return resp, nil, fmt.Errorf("reading response body: %w", err)
	}

	return resp, body, nil
}

// Get is a convenience wrapper for GET requests.
func (h *HTTPClient) Get(ctx context.Context, rawURL string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	return h.Do(ctx, req)
}

// randomUA picks a random User‑Agent from the pool.
func (h *HTTPClient) randomUA() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.userAgents) == 0 {
		return "Scann3r/1.0"
	}
	return h.userAgents[h.rng.Intn(len(h.userAgents))]
}
