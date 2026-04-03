// Package main provides a deliberately vulnerable web server for testing Venom.
// DO NOT deploy this anywhere — it contains intentional security flaws.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

const addr = ":8888"

func main() {
	mux := http.NewServeMux()

	// ─── Home page with links, forms, and inline JS ──────────────────────
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Vulnerable Test App</title></head>
<body>
<h1>⚡ Scann3r Test Target</h1>
<p>This app has intentional vulnerabilities for testing.</p>

<h2>Pages</h2>
<ul>
  <li><a href="/search?q=test">Search</a></li>
  <li><a href="/user?id=1">User Profile</a></li>
  <li><a href="/login">Login Form</a></li>
  <li><a href="/redirect?url=/">Redirect</a></li>
  <li><a href="/file?name=readme.txt">File Viewer</a></li>
  <li><a href="/template?name=World">Template</a></li>
  <li><a href="/admin">Admin (hidden)</a></li>
  <li><a href="/api/v1/users">API Endpoint</a></li>
</ul>

<h2>Contact Form</h2>
<form action="/submit" method="POST">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="text" name="name" placeholder="Name">
  <input type="email" name="email" placeholder="Email">
  <textarea name="message" placeholder="Message"></textarea>
  <button type="submit">Send</button>
</form>

<script>
// Inline JS with API endpoints for the JS parser to discover
const API_BASE = "/api/v1";
fetch("/api/v1/config");
const endpoints = {
  users: "/api/v1/users",
  admin: "/api/internal/admin",
  debug: "/api/debug/vars",
  secret_key: "sk_test_1234567890abcdef"
};
</script>
<script src="/static/app.js"></script>
</body>
</html>`)
	})

	// ─── Reflected XSS: search query echoed without encoding ─────────────
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		// VULNERABLE: directly echoing user input
		fmt.Fprintf(w, `<html><body><h1>Search Results</h1>
<p>You searched for: %s</p>
<p>No results found.</p>
<a href="/">Back</a>
</body></html>`, q)
	})

	// ─── SQL error disclosure: fake DB error on special input ────────────
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html")

		// Simulate SQL error when input contains quotes
		for _, c := range id {
			if c == '\'' || c == '"' || c == '-' {
				w.WriteHeader(500)
				fmt.Fprintf(w, `<html><body>
<h1>Internal Server Error</h1>
<p>You have an error in your SQL syntax; check the manual near '%s' at line 1</p>
<p>Query: SELECT * FROM users WHERE id = '%s'</p>
</body></html>`, id, id)
				return
			}
		}

		fmt.Fprintf(w, `<html><body>
<h1>User Profile</h1>
<p>User ID: %s</p>
<p>Name: Test User</p>
<a href="/">Back</a>
</body></html>`, id)
	})

	// ─── Login form (POST target) ────────────────────────────────────────
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method == "POST" {
			user := r.FormValue("username")
			// VULNERABLE: reflected in response
			fmt.Fprintf(w, `<html><body>
<p>Login failed for user: %s</p>
<a href="/login">Try again</a>
</body></html>`, user)
			return
		}
		fmt.Fprint(w, `<html><body>
<h1>Login</h1>
<form method="POST" action="/login">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <input type="hidden" name="next" value="/dashboard">
  <button type="submit">Login</button>
</form>
</body></html>`)
	})

	// ─── Open redirect ───────────────────────────────────────────────────
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target != "" {
			// VULNERABLE: no validation on redirect target
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// ─── LFI simulation: echoes the filename in error ────────────────────
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html")
		if name == "" {
			fmt.Fprint(w, `<p>No file specified</p>`)
			return
		}
		// Simulate LFI error disclosure
		if len(name) > 10 || name[0] == '.' || name[0] == '/' {
			w.WriteHeader(500)
			fmt.Fprintf(w, `<html><body>
<p>PHP Warning: include(%s): failed to open stream: No such file or directory</p>
<p>root:x:0:0:root:/root:/bin/bash</p>
</body></html>`, name)
			return
		}
		fmt.Fprintf(w, `<html><body><p>File contents: [%s placeholder]</p></body></html>`, name)
	})

	// ─── Template injection simulation ───────────────────────────────────
	mux.HandleFunc("/template", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html")
		// Simulate SSTI: if input is {{7*7}}, return 49
		if name == "{{7*7}}" {
			fmt.Fprint(w, `<html><body><p>Hello, 49!</p></body></html>`)
			return
		}
		// Reflect input (also XSS)
		fmt.Fprintf(w, `<html><body><p>Hello, %s!</p></body></html>`, name)
	})

	// ─── POST form handler (reflects input) ──────────────────────────────
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		r.ParseForm()
		name := r.FormValue("name")
		msg := r.FormValue("message")
		w.Header().Set("Content-Type", "text/html")
		// VULNERABLE: reflected without encoding
		fmt.Fprintf(w, `<html><body>
<h1>Message Received</h1>
<p>From: %s</p>
<p>Message: %s</p>
<a href="/">Back</a>
</body></html>`, name, msg)
	})

	// ─── Hidden API endpoints ────────────────────────────────────────────
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"users":[{"id":1,"name":"admin","role":"superuser"},{"id":2,"name":"test","role":"user"}]}`)
	})

	mux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// VULNERABLE: information disclosure
		fmt.Fprint(w, `{"debug":true,"database":"mysql://root:password123@localhost:3306/app","secret_key":"supersecretkey123","version":"2.1.3"}`)
	})

	mux.HandleFunc("/api/internal/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"admin panel","users_count":1547,"server":"10.0.0.42:8080"}`)
	})

	mux.HandleFunc("/api/debug/vars", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"goroutines":42,"memory_mb":128,"uptime":"72h","internal_ip":"192.168.1.100:9090"}`)
	})

	// ─── Fake JS file with embedded endpoints ────────────────────────────
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `
// Main application JS
const BASE_URL = "/api/v1";

async function loadUsers() {
  const resp = await fetch("/api/v1/users");
  return resp.json();
}

function getConfig() {
  return axios.get("/api/v1/config");
}

const HIDDEN_ENDPOINTS = {
  backup: "/api/internal/backup",
  logs: "/api/internal/logs",
  metrics: "/api/metrics/prometheus",
  health: "/api/health",
};

// Development token (oops)
const DEV_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.devtoken";
const API_KEY = "ak_live_9f8e7d6c5b4a3210";
`)
	})

	// ─── Admin page (hidden, not linked except from JS) ──────────────────
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
<h1>Admin Panel</h1>
<form method="POST" action="/admin/execute">
  <input type="text" name="cmd" placeholder="Command">
  <button type="submit">Execute</button>
</form>
</body></html>`)
	})

	mux.HandleFunc("/admin/execute", func(w http.ResponseWriter, r *http.Request) {
		cmd := r.FormValue("cmd")
		w.Header().Set("Content-Type", "text/html")
		// Simulate command injection error
		if cmd != "" {
			w.WriteHeader(500)
			fmt.Fprintf(w, `<p>command not found: %s</p><p>sh: syntax error</p>`, cmd)
			return
		}
		fmt.Fprint(w, `<p>No command specified</p>`)
	})

	// ─── robots.txt ──────────────────────────────────────────────────────
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, `User-agent: *
Disallow: /admin
Disallow: /api/internal/
Disallow: /api/debug/
Disallow: /backup/
Sitemap: http://localhost:8888/sitemap.xml
`)
	})

	// ─── sitemap.xml ─────────────────────────────────────────────────────
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://localhost:8888/</loc></url>
  <url><loc>http://localhost:8888/search?q=example</loc></url>
  <url><loc>http://localhost:8888/user?id=1</loc></url>
  <url><loc>http://localhost:8888/login</loc></url>
  <url><loc>http://localhost:8888/file?name=readme.txt</loc></url>
  <url><loc>http://localhost:8888/template?name=World</loc></url>
</urlset>`)
	})

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  🎯 Vulnerable Test Server")
	fmt.Println("  Running on http://localhost" + addr)
	fmt.Println("  ")
	fmt.Println("  Intentional vulnerabilities:")
	fmt.Println("  • Reflected XSS     → /search?q=")
	fmt.Println("  • SQL Injection     → /user?id=")
	fmt.Println("  • Open Redirect     → /redirect?url=")
	fmt.Println("  • LFI Simulation    → /file?name=")
	fmt.Println("  • SSTI Simulation   → /template?name=")
	fmt.Println("  • Info Disclosure   → /api/v1/config")
	fmt.Println("  • Hidden Endpoints  → JS parser should find these")
	fmt.Println("  • Command Injection → /admin/execute")
	fmt.Println("  ")
	fmt.Println("  Press Ctrl+C to stop")
	fmt.Println("═══════════════════════════════════════════════════════")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
