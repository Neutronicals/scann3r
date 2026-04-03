// Package analyzer inspects fuzz results for evidence of vulnerabilities.
// It streams Findings onto a channel the moment they are confirmed.
package analyzer

import (
	"context"
	"sync"

	"github.com/venom-scanner/venom/internal/models"
)

// Analyzer reads FuzzResults, passes them through multiple detection
// strategies, and emits Findings. It runs its own goroutine pool internally.
type Analyzer struct {
	detector *Detector
	timer    *TimingDetector
	stats    *models.ScanStats
	workers  int
}

// NewAnalyzer creates an Analyzer with the given concurrency level.
func NewAnalyzer(stats *models.ScanStats, workers int) *Analyzer {
	if workers < 1 {
		workers = 5
	}
	return &Analyzer{
		detector: NewDetector(),
		timer:    NewTimingDetector(),
		stats:    stats,
		workers:  workers,
	}
}

// Analyze reads from the results channel, inspects each result, and sends
// confirmed findings to the findings channel. Blocks until results is closed.
func (a *Analyzer) Analyze(ctx context.Context, results <-chan *models.FuzzResult, findings chan<- *models.Finding) {
	var wg sync.WaitGroup

	for i := 0; i < a.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.worker(ctx, results, findings)
		}()
	}

	wg.Wait()
}

// worker is a single analysis goroutine.
func (a *Analyzer) worker(ctx context.Context, results <-chan *models.FuzzResult, findings chan<- *models.Finding) {
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-results:
			if !ok {
				return
			}
			if result.Error != nil {
				continue
			}
			a.inspect(ctx, result, findings)
		}
	}
}

// inspect runs all detection strategies against a single result.
func (a *Analyzer) inspect(ctx context.Context, result *models.FuzzResult, findings chan<- *models.Finding) {
	// 1. Pattern-based detection (reflected payloads, error messages)
	patternFindings := a.detector.Detect(result)
	for _, f := range patternFindings {
		a.stats.AddFinding(f.Severity)
		select {
		case findings <- f:
		case <-ctx.Done():
			return
		}
	}

	// 2. Timing-based detection (blind SQL injection, command injection)
	timingFindings := a.timer.Detect(result)
	for _, f := range timingFindings {
		a.stats.AddFinding(f.Severity)
		select {
		case findings <- f:
		case <-ctx.Done():
			return
		}
	}
}
