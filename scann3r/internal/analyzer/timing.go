package analyzer

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/venom-scanner/venom/internal/models"
)

// TimingDetector identifies blind vulnerabilities by measuring response
// time anomalies. A response that takes ≥ the expected sleep duration is
// flagged as a potential time‑based blind injection.
type TimingDetector struct {
	// Minimum response time (relative to the injected sleep) to trigger a finding.
	// E.g. if the payload says SLEEP(5), we expect ≥4 seconds (accounting for jitter).
	thresholdRatio float64
}

// NewTimingDetector creates a TimingDetector with sane defaults.
func NewTimingDetector() *TimingDetector {
	return &TimingDetector{
		thresholdRatio: 0.8, // response must be ≥80% of the sleep duration
	}
}

// Detect checks if the response time is consistent with a time‑based
// blind injection. Returns findings if the timing matches.
func (t *TimingDetector) Detect(result *models.FuzzResult) []*models.Finding {
	if result == nil || result.Task == nil {
		return nil
	}

	sleepDuration := t.extractSleepDuration(result.Payload)
	if sleepDuration == 0 {
		return nil
	}

	// Did the response actually take long enough?
	threshold := time.Duration(float64(sleepDuration) * t.thresholdRatio)
	if result.ResponseTime < threshold {
		return nil
	}

	// Determine vuln type based on payload content
	vulnType := "sqli"
	severity := "critical"
	if containsAny(result.Payload, "sleep ", "ping ", "|sleep", ";sleep", "$(sleep") {
		vulnType = "cmdi"
	}

	return []*models.Finding{
		{
			ID:                uuid.New().String(),
			URL:               result.Task.URL,
			Method:            result.Task.Method,
			Parameter:         result.Task.Parameter.Name,
			ParameterLocation: result.Task.Parameter.Location,
			Type:              vulnType,
			Severity:          severity,
			Payload:           result.Payload,
			MutationStrategy:  result.MutationName,
			Evidence: formatTimingEvidence(
				result.Payload, sleepDuration, result.ResponseTime,
			),
			Confidence: t.calculateConfidence(sleepDuration, result.ResponseTime),
			FoundAt:    time.Now(),
		},
	}
}

// extractSleepDuration parses known sleep/delay patterns from a payload
// and returns the expected duration.
func (t *TimingDetector) extractSleepDuration(payload string) time.Duration {
	lower := strings.ToLower(payload)

	// SLEEP(N) — MySQL
	if d := extractSeconds(lower, "sleep(", ")"); d > 0 {
		return d
	}
	// pg_sleep(N) — PostgreSQL
	if d := extractSeconds(lower, "pg_sleep(", ")"); d > 0 {
		return d
	}
	// WAITFOR DELAY '0:0:N' — MSSQL
	if d := extractWaitforDelay(lower); d > 0 {
		return d
	}
	// ;sleep N — command injection
	if d := extractSeconds(lower, "sleep ", ""); d > 0 {
		return d
	}
	// ping -c N — command injection time‑based
	if d := extractSeconds(lower, "ping -c ", " "); d > 0 {
		return d
	}
	if d := extractSeconds(lower, "ping -n ", " "); d > 0 {
		return d
	}

	return 0
}

// extractSeconds pulls a numeric duration from between a prefix and suffix.
func extractSeconds(s, prefix, suffix string) time.Duration {
	idx := strings.Index(s, prefix)
	if idx == -1 {
		return 0
	}
	rest := s[idx+len(prefix):]
	var end int
	if suffix == "" {
		// Read until non-digit
		for end = 0; end < len(rest); end++ {
			if rest[end] < '0' || rest[end] > '9' {
				break
			}
		}
	} else {
		end = strings.Index(rest, suffix)
		if end == -1 {
			end = len(rest)
		}
	}
	numStr := strings.TrimSpace(rest[:end])
	var seconds int
	for _, c := range numStr {
		if c >= '0' && c <= '9' {
			seconds = seconds*10 + int(c-'0')
		} else {
			break
		}
	}
	if seconds > 0 && seconds <= 30 { // cap at 30s to reject bogus values
		return time.Duration(seconds) * time.Second
	}
	return 0
}

// extractWaitforDelay parses MSSQL "WAITFOR DELAY '0:0:N'" syntax.
func extractWaitforDelay(s string) time.Duration {
	marker := "waitfor delay '"
	idx := strings.Index(s, marker)
	if idx == -1 {
		return 0
	}
	rest := s[idx+len(marker):]
	endIdx := strings.Index(rest, "'")
	if endIdx == -1 {
		return 0
	}
	parts := strings.Split(rest[:endIdx], ":")
	if len(parts) < 3 {
		return 0
	}
	// Parse the seconds part (last element)
	var seconds int
	for _, c := range parts[2] {
		if c >= '0' && c <= '9' {
			seconds = seconds*10 + int(c-'0')
		}
	}
	if seconds > 0 && seconds <= 30 {
		return time.Duration(seconds) * time.Second
	}
	return 0
}

// calculateConfidence assigns a confidence score based on how closely
// the response time matches the expected sleep duration.
func (t *TimingDetector) calculateConfidence(expected, actual time.Duration) float64 {
	ratio := float64(actual) / float64(expected)
	switch {
	case ratio >= 0.95 && ratio <= 1.2:
		return 0.95 // very close to expected
	case ratio >= 0.8 && ratio < 0.95:
		return 0.80
	case ratio > 1.2 && ratio <= 2.0:
		return 0.70
	default:
		return 0.60
	}
}

// formatTimingEvidence creates a human‑readable evidence string.
func formatTimingEvidence(payload string, expected, actual time.Duration) string {
	return "Time-based detection: payload '" + payload +
		"' expected delay " + expected.String() +
		", actual response time " + actual.String()
}

// containsAny returns true if s contains any of the substrings.
func containsAny(s string, subs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}
