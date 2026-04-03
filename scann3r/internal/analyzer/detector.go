package analyzer

import (
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/venom-scanner/venom/internal/models"
)

// indicatorSet groups detection patterns by vulnerability category.
type indicatorSet struct {
	Category   string
	Severity   string
	Indicators []string        // simple substring matches
	Regexes    []*regexp.Regexp // compiled regex patterns
}

// Detector performs pattern‑based vulnerability detection on HTTP responses.
type Detector struct {
	indicators []indicatorSet
}

// NewDetector builds a Detector with all built‑in indicator sets.
func NewDetector() *Detector {
	return &Detector{
		indicators: []indicatorSet{
			// --- SQL Injection (Error‑Based) ---
			{
				Category: "sqli",
				Severity: "critical",
				Indicators: []string{
					"SQL syntax", "mysql_fetch", "mysql_num_rows", "mysql_query",
					"pg_query", "pg_exec", "ORA-01756", "ORA-00933", "ORA-00921",
					"SQLite3::", "sqlite_error", "SQLITE_ERROR",
					"Microsoft OLE DB", "ODBC SQL Server", "ODBC Microsoft Access",
					"JET Database Engine", "mssql_query",
					"Unclosed quotation mark", "quoted string not properly terminated",
					"You have an error in your SQL syntax",
					"supplied argument is not a valid MySQL",
					"unterminated quoted string", "invalid input syntax for",
					"syntax error at or near", "ERROR: parser:",
					"DB2 SQL error", "SQLCODE", "SQLSTATE",
					"Sybase message", "Informix ODBC",
					"DriverSapDB", "com.sap.dbtech",
					"pg_sleep", "WAITFOR DELAY",
				},
			},

			// --- XSS (Reflected) ---
			{
				Category: "xss",
				Severity: "high",
				Indicators: []string{}, // XSS detected by reflection check below
			},

			// --- Command Injection ---
			{
				Category: "cmdi",
				Severity: "critical",
				Indicators: []string{
					"uid=", "gid=", "root:x:0", "bin/bash", "bin/sh",
					"/etc/passwd", "command not found", "not recognized as",
				},
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`uid=\d+\([\w]+\)\s+gid=\d+`),
					regexp.MustCompile(`(?:root|daemon|nobody):x:\d+:\d+`),
					regexp.MustCompile(`Linux\s+\S+\s+\d+\.\d+`),
				},
			},

			// --- SSRF ---
			{
				Category: "ssrf",
				Severity: "high",
				Indicators: []string{
					"ami-id", "instance-id", "instance-type", "security-credentials",
					"AccessKeyId", "SecretAccessKey", "computeMetadata",
					"redis_version",
				},
			},

			// --- LFI ---
			{
				Category: "lfi",
				Severity: "high",
				Indicators: []string{
					"root:x:0", "root:*:0", "daemon:x:", "nobody:x:",
					"for 16-bit app support", "[extensions]", "[fonts]",
				},
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`[a-z]+:x:\d+:\d+:`), // /etc/passwd format
				},
			},

			// --- SSTI ---
			{
				Category: "ssti",
				Severity: "critical",
				Indicators: []string{
					"__class__", "__subclasses__", "__globals__", "__builtins__",
					"flask.app", "jinja2", "Twig", "Freemarker",
					"Velocity", "Thymeleaf",
				},
			},

			// --- Information Disclosure ---
			{
				Category: "info_disclosure",
				Severity: "low",
				Indicators: []string{
					"stack trace", "Traceback (most recent call last)",
					"at java.", "at sun.", "at org.apache",
					"PHP Fatal error", "PHP Warning", "PHP Notice",
					"X-Powered-By:", "Server:",
					"wp-config.php", "database.yml", ".env",
				},
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)(?:password|passwd|secret|api.?key)\s*[:=]\s*\S+`),
					regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+`), // internal IP:port
				},
			},
		},
	}
}

// Detect checks a FuzzResult against all indicator sets and returns any findings.
func (d *Detector) Detect(result *models.FuzzResult) []*models.Finding {
	if result == nil || result.Task == nil || len(result.ResponseBody) == 0 {
		return nil
	}

	var findings []*models.Finding
	body := string(result.ResponseBody)

	// --- XSS Reflection Check ---
	// The definitive XSS test: does the injected payload appear verbatim
	// in the response body (meaning it was reflected without encoding)?
	if result.Payload != "" && strings.Contains(body, result.Payload) {
		// Check if it looks like an actual XSS payload (contains HTML/JS)
		if looksLikeXSS(result.Payload) {
			findings = append(findings, &models.Finding{
				ID:                uuid.New().String(),
				URL:               result.Task.URL,
				Method:            result.Task.Method,
				Parameter:         result.Task.Parameter.Name,
				ParameterLocation: result.Task.Parameter.Location,
				Type:              "xss",
				Severity:          "high",
				Payload:           result.Payload,
				MutationStrategy:  result.MutationName,
				Evidence:          truncate(extractContext(body, result.Payload, 100), 500),
				Confidence:        0.85,
				FoundAt:           time.Now(),
			})
		}
	}

	// --- SSTI Arithmetic Check ---
	// If we injected {{7*7}} and see "49" in the response, it's SSTI.
	if strings.Contains(result.Payload, "7*7") && strings.Contains(body, "49") {
		findings = append(findings, &models.Finding{
			ID:                uuid.New().String(),
			URL:               result.Task.URL,
			Method:            result.Task.Method,
			Parameter:         result.Task.Parameter.Name,
			ParameterLocation: result.Task.Parameter.Location,
			Type:              "ssti",
			Severity:          "critical",
			Payload:           result.Payload,
			MutationStrategy:  result.MutationName,
			Evidence:          "Template expression {{7*7}} evaluated to 49",
			Confidence:        0.90,
			FoundAt:           time.Now(),
		})
	}

	// --- Pattern‑Based Indicator Matching ---
	for _, iset := range d.indicators {
		for _, indicator := range iset.Indicators {
			if strings.Contains(body, indicator) {
				findings = append(findings, &models.Finding{
					ID:                uuid.New().String(),
					URL:               result.Task.URL,
					Method:            result.Task.Method,
					Parameter:         result.Task.Parameter.Name,
					ParameterLocation: result.Task.Parameter.Location,
					Type:              iset.Category,
					Severity:          iset.Severity,
					Payload:           result.Payload,
					MutationStrategy:  result.MutationName,
					Evidence:          truncate(extractContext(body, indicator, 80), 500),
					Confidence:        0.70,
					FoundAt:           time.Now(),
				})
				break // one finding per category per result
			}
		}

		// Regex patterns
		for _, rx := range iset.Regexes {
			if loc := rx.FindString(body); loc != "" {
				findings = append(findings, &models.Finding{
					ID:                uuid.New().String(),
					URL:               result.Task.URL,
					Method:            result.Task.Method,
					Parameter:         result.Task.Parameter.Name,
					ParameterLocation: result.Task.Parameter.Location,
					Type:              iset.Category,
					Severity:          iset.Severity,
					Payload:           result.Payload,
					MutationStrategy:  result.MutationName,
					Evidence:          truncate(loc, 500),
					Confidence:        0.75,
					FoundAt:           time.Now(),
				})
				break
			}
		}
	}

	// --- Status Code Anomalies ---
	if result.StatusCode == 500 {
		findings = append(findings, &models.Finding{
			ID:                uuid.New().String(),
			URL:               result.Task.URL,
			Method:            result.Task.Method,
			Parameter:         result.Task.Parameter.Name,
			ParameterLocation: result.Task.Parameter.Location,
			Type:              "error",
			Severity:          "medium",
			Payload:           result.Payload,
			MutationStrategy:  result.MutationName,
			Evidence:          "Server returned 500 Internal Server Error",
			Confidence:        0.50,
			FoundAt:           time.Now(),
		})
	}

	return findings
}

// looksLikeXSS returns true if the payload contains HTML/JS-like syntax.
func looksLikeXSS(payload string) bool {
	xssMarkers := []string{
		"<script", "<img", "<svg", "<body", "<input", "<details",
		"<marquee", "<video", "<audio", "<iframe",
		"onerror=", "onload=", "onfocus=", "ontoggle=", "onstart=",
		"javascript:", "alert(", "confirm(", "prompt(",
	}
	lower := strings.ToLower(payload)
	for _, marker := range xssMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// extractContext returns a snippet of text centered around the match.
func extractContext(body, match string, padding int) string {
	idx := strings.Index(body, match)
	if idx == -1 {
		return match
	}
	start := idx - padding
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + padding
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}

// truncate shortens a string to maxLen, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
