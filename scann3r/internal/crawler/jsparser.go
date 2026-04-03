package crawler

import (
	"regexp"
	"strings"
)

// Regex patterns for extracting API endpoints and URLs from JavaScript source.
var jsPatterns = []*regexp.Regexp{
	// fetch("/api/v1/users")  or  fetch('/api/v1/users')
	regexp.MustCompile(`fetch\s*\(\s*['"]([^'"]+)['"]\s*`),

	// axios.get("/api/endpoint")  axios.post(...)  axios.put(...)  axios.delete(...)
	regexp.MustCompile(`axios\.\w+\s*\(\s*['"]([^'"]+)['"]\s*`),

	// $.ajax({ url: "/api/..." })  or  $.get("/api/...")  $.post(...)
	regexp.MustCompile(`\$\.\w+\s*\(\s*['"]([^'"]+)['"]\s*`),

	// XMLHttpRequest .open("GET", "/api/...")
	regexp.MustCompile(`\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]\s*`),

	// url: "/api/..."  or  endpoint: "/api/..."  or  path: "/api/..."
	regexp.MustCompile(`(?:url|endpoint|path|api_?url|base_?url|api_?path)\s*[:=]\s*['"]([^'"]+)['"]`),

	// Generic path-like strings: "/api/v1/something" or "/admin/dashboard"
	regexp.MustCompile(`['"](\/(?:api|v[0-9]+|admin|auth|user|account|dashboard|internal|graphql|rest|ws|webhook|callback|oauth|login|register|upload|download|search|config|settings|health|status|metrics)[^\s'"]*)['"]\s*`),

	// Relative paths starting with ./  or ../
	regexp.MustCompile(`['"](\.\./[a-zA-Z0-9_/.-]+)['"]\s*`),
	regexp.MustCompile(`['"](\./[a-zA-Z0-9_/.-]+)['"]\s*`),

	// Full URLs embedded in JS: "https://api.example.com/v1/users"
	regexp.MustCompile(`['"](https?://[^\s'"<>]+)['"]\s*`),
}

// Patterns for interesting secrets/tokens in JS (informational finding)
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret|token|password|passwd|authorization)\s*[:=]\s*['"]([^'"]{8,})['"]\s*`),
	regexp.MustCompile(`(?i)(?:aws[_-]?access|aws[_-]?secret)\s*[:=]\s*['"]([^'"]+)['"]\s*`),
	regexp.MustCompile(`(?i)Bearer\s+([a-zA-Z0-9._-]{20,})`),
}

// ExtractJSEndpoints parses JavaScript source code and returns a deduplicated
// list of URL‑like strings (API routes, paths, full URLs).
func ExtractJSEndpoints(jsCode string) []string {
	seen := make(map[string]bool)
	var endpoints []string

	for _, pat := range jsPatterns {
		matches := pat.FindAllStringSubmatch(jsCode, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			ep := strings.TrimSpace(m[1])
			if ep == "" || seen[ep] {
				continue
			}
			// Filter out common false positives
			if isJSFalsePositive(ep) {
				continue
			}
			seen[ep] = true
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

// ExtractJSSecrets scans JS source for hardcoded API keys, tokens, and
// secrets. Returns a list of "type: value" strings.
func ExtractJSSecrets(jsCode string) []string {
	seen := make(map[string]bool)
	var secrets []string

	for _, pat := range secretPatterns {
		matches := pat.FindAllStringSubmatch(jsCode, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			secret := strings.TrimSpace(m[1])
			if secret == "" || seen[secret] {
				continue
			}
			seen[secret] = true
			secrets = append(secrets, m[0])
		}
	}

	return secrets
}

// isJSFalsePositive filters out strings that look like paths but are
// actually JS keywords, CSS selectors, or common noise.
func isJSFalsePositive(s string) bool {
	// Too short to be interesting
	if len(s) < 2 {
		return true
	}

	// Common JS/CSS false positives
	falsePositives := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".map",
		"text/", "application/json", "application/x-www-form-urlencoded",
		"multipart/form-data", "charset=", "Content-Type",
		"true", "false", "null", "undefined",
	}
	lower := strings.ToLower(s)
	for _, fp := range falsePositives {
		if s == fp || lower == fp {
			return true
		}
	}

	// Only file extension, no path component (e.g., "file.png")
	if !strings.Contains(s, "/") && strings.Contains(s, ".") {
		parts := strings.Split(s, ".")
		ext := parts[len(parts)-1]
		staticExts := map[string]bool{
			"js": true, "css": true, "png": true, "jpg": true,
			"gif": true, "svg": true, "ico": true, "map": true,
			"woff": true, "woff2": true, "ttf": true, "eot": true,
		}
		if staticExts[ext] {
			return true
		}
	}

	return false
}
