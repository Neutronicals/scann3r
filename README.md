# 🛡️ Scann3r — High-Performance Asynchronous Web Vulnerability Scanner

```text
 ██████╗  ██████╗ █████╗ ███╗   ██╗███╗   ██╗ ██████╗ ██████╗ 
██╔════╝ ██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝ ██╔══██╗
╚█████╗  ██║     ███████║██╔██╗ ██║██╔██╗ ██║╚█████╗  ██████╔╝
 ╚═══██╗ ██║     ██╔══██║██║╚██╗██║██║╚██╗██║ ╚═══██╗ ██╔══██╗
██████╔╝ ╚██████╗██║  ██║██║ ╚████║██║ ╚████║██████╔╝ ██║  ██║
╚═════╝   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚═════╝  ╚═╝  ╚═╝
```

**Scann3r** is a state-of-the-art, high-performance web vulnerability scanner written in **Go**. Designed for security professionals and ethical hackers, it features a highly concurrent streaming pipeline architecture that allows for rapid discovery and analysis of web security flaws.

> [!CAUTION]
> ### 🛑 LEGAL & ETHICAL DISCLAIMER
> 
> **Scann3r is intended for AUTHORIZED security testing and EDUCATIONAL purposes only.** 
> 
> *   **Usage without Consent:** Scanning targets without explicit, written permission from the owner is illegal and unethical. It is the user's responsibility to obey all applicable local, state, and federal laws.
> *   **Liability:** The developers of Scann3r assume **no liability** and are not responsible for any misuse or damage caused by this program.
> *   **Authorized Use Only:** This tool should only be used as part of a formal security assessment or bug bounty program where permission is granted.
> 
> **By using this software, you agree to these terms.**

---

## 🚀 Key Features

### 🕷️ Intelligent Crawler & Spider
- **Recursive Discovery:** Crawls HTML pages to a configurable depth.
- **JS Endpoint Mining:** Extracts API routes and hidden endpoints from JavaScript files (`fetch`, `axios`, etc.).
- **Form Analysis:** Automatically detects and extracts parameters from forms, inputs, and AJAX requests.
- **Asset Scraping:** Parses `robots.txt` and `sitemaps.xml` for potential targets.

### ⚡ Concurrent Streaming Pipeline
- **Zero-Latency Processing:** Discovered URLs are fed into the fuzzer immediately via Go channels.
- **Highly Parallel:** Utilizes goroutine pools for crawling (default: 20) and fuzzing (default: 30).
- **Intelligent Rate Limiting:** Built-in per-domain token bucket rate limiting to prevent overloading targets.

### 🔀 Advanced Mutation Engine (WAF Bypass)
Scann3r includes 10+ mutation strategies to evade Web Application Firewalls (WAFs) and IDS/IPS systems:
- **Encoding Bypass:** Double URL, HTML Entity, Unicode, and Hex encoding.
- **Obfuscation:** Case randomization, whitespace variation, and string concatenation.
- **Injection:** SQL comment injection and null-byte bypasses.

### 🎯 Vulnerability Detection Modules
Comprehensive coverage for critical web vulnerabilities:
- **Injection:** SQLi (Error-based, Union, Blind), Command Injection (OS-specific).
- **Client-Side:** XSS (Reflected, DOM, Event-based).
- **Server-Side:** SSRF (Cloud Metadata, Localhost), LFI (Path Traversal), SSTI (Jinja2, Twig, etc.).
- **Logic:** Open Redirects and Information Disclosure.

### 📊 Real-time Dashboard (TUI)
- Visual monitoring of scan progress, request rates, and discovery stats.
- Live severity-colored findings feed.
- Built using the **Bubble Tea** (Charm) framework for a premium terminal experience.

---

## 🛠️ Installation

### From Source
Ensure you have **Go 1.25+** installed.

```bash
# Clone the repository
git clone https://github.com/venom-scanner/venom.git
cd venom

# Build the binary
go mod tidy
go build -o scann3r.exe ./cmd/venom/
```

---

## 📖 Usage

### Basic Scan
```bash
# Start a scan with the terminal dashboard
./scann3r scan --target https://example.com

# Headless mode (CLI only, useful for CI/CD or automation)
./scann3r scan --target https://example.com --headless --verbose
```

### Advanced Configuration
```bash
./scann3r scan --target https://example.com \
  --depth 5 \
  --crawl-threads 40 \
  --fuzz-threads 60 \
  --rate 15 \
  --output result.html \
  --format html
```

### Global Flags
| Flag | Description | Default |
|---|---|---|
| `-t, --target` | Target URL to scan (Required) | - |
| `-d, --depth` | Maximum crawling depth | 3 |
| `--crawl-threads`| Number of concurrent crawler routines | 20 |
| `--fuzz-threads` | Number of concurrent fuzzer routines | 30 |
| `-r, --rate` | Max requests per second | 10 |
| `-o, --output` | Output report filename | - |
| `-f, --format` | Report format (json, html, md) | json |
| `--headless` | Run without the GUI/TUI dashboard | false |

---

## 📂 Project Structure

```text
scann3r/
├── cmd/                # CLI entry points
├── internal/
│   ├── crawler/        # Spider & asset discovery
│   ├── scanner/        # Fuzzing & payload injection
│   ├── analyzer/       # Vulnerability detection logic
│   ├── storage/        # SQLite persistence layer
│   └── reporter/       # HTML/JSON/MD report generation
├── reports/            # Generated scan reports
└── scann3r.db          # Scan database
```

---

## 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request or open an issue.

## 📄 License
This project is licensed under the [MIT License](LICENSE) - see the file for details.

---
**Disclaimer:** *The tool name and branding "Scann3r" is used for identification of this specific project fork/version.*
