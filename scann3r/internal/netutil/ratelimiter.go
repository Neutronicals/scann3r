package netutil

import (
	"context"
	"net/url"
	"sync"

	"golang.org/x/time/rate"
)

// DomainRateLimiter enforces per‑domain request throttling using the
// token‑bucket algorithm. Each unique hostname gets its own limiter so
// scanning multiple sub‑domains doesn't starve any single target.
type DomainRateLimiter struct {
	mu       sync.RWMutex
	limiters map[string]*rate.Limiter
	rps      rate.Limit // requests per second
	burst    int        // max burst size
}

// NewDomainRateLimiter creates a rate limiter that allows `rps` sustained
// requests/sec per domain with a burst capacity of max(1, rps).
func NewDomainRateLimiter(rps float64) *DomainRateLimiter {
	burst := int(rps)
	if burst < 1 {
		burst = 1
	}
	return &DomainRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
}

// Wait blocks until the caller is allowed to send a request to the given URL.
// It returns immediately if the context is cancelled.
func (d *DomainRateLimiter) Wait(ctx context.Context, rawURL string) error {
	host := extractHost(rawURL)
	limiter := d.getLimiter(host)
	return limiter.Wait(ctx)
}

// Allow is the non‑blocking version: returns true if a request can be sent now.
func (d *DomainRateLimiter) Allow(rawURL string) bool {
	host := extractHost(rawURL)
	limiter := d.getLimiter(host)
	return limiter.Allow()
}

// BackOff halves the rate for a domain (called when we get a 429).
func (d *DomainRateLimiter) BackOff(rawURL string) {
	host := extractHost(rawURL)
	d.mu.Lock()
	defer d.mu.Unlock()
	if lim, ok := d.limiters[host]; ok {
		newRate := lim.Limit() / 2
		if newRate < 0.5 {
			newRate = 0.5 // floor at 1 request every 2 seconds
		}
		lim.SetLimit(newRate)
	}
}

// getLimiter returns (or lazily creates) the limiter for a host.
func (d *DomainRateLimiter) getLimiter(host string) *rate.Limiter {
	// Fast path: read lock
	d.mu.RLock()
	lim, ok := d.limiters[host]
	d.mu.RUnlock()
	if ok {
		return lim
	}

	// Slow path: create under write lock
	d.mu.Lock()
	defer d.mu.Unlock()
	// Double‑check after acquiring write lock
	if lim, ok = d.limiters[host]; ok {
		return lim
	}
	lim = rate.NewLimiter(d.rps, d.burst)
	d.limiters[host] = lim
	return lim
}

// extractHost pulls the hostname from a raw URL string.
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL // fall back to using the raw string as key
	}
	return u.Host
}
