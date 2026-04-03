// Package ui provides a real‑time terminal dashboard for Venom scans
// using the Bubble Tea framework.
package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/venom-scanner/venom/internal/models"
)

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#60efff")).
			Background(lipgloss.Color("#0a0a1a")).
			Padding(0, 2)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#1f2937")).
			Padding(1, 2)

	statLabelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888"))

	statValueStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#60efff"))

	criticalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ff0044")).
			Bold(true)

	highStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ff8800")).
			Bold(true)

	mediumStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ffcc00")).
			Bold(true)

	lowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#0088ff")).
			Bold(true)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00ff87"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#555555"))

	logStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#aaaaaa"))
)

// ---------------------------------------------------------------------------
// Bubble Tea model
// ---------------------------------------------------------------------------

// tickMsg triggers a UI refresh.
type tickMsg time.Time

// Dashboard is the Bubble Tea model for the Venom TUI.
type Dashboard struct {
	stats     *models.ScanStats
	target    string
	scanID    string
	logs      []string // most recent log lines
	maxLogs   int
	width     int
	height    int
	quitting  bool
	done      bool

	// Findings feed (latest findings for display)
	findings []*models.Finding
	maxFindings int
}

// NewDashboard creates a Dashboard model.
func NewDashboard(stats *models.ScanStats, target, scanID string) *Dashboard {
	return &Dashboard{
		stats:       stats,
		target:      target,
		scanID:      scanID,
		maxLogs:     8,
		maxFindings: 5,
		width:       80,
		height:      30,
	}
}

// AddLog appends a log line to the dashboard feed.
func (d *Dashboard) AddLog(msg string) {
	d.logs = append(d.logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	if len(d.logs) > d.maxLogs {
		d.logs = d.logs[len(d.logs)-d.maxLogs:]
	}
}

// AddFinding adds a finding to the dashboard feed.
func (d *Dashboard) AddFinding(f *models.Finding) {
	d.findings = append([]*models.Finding{f}, d.findings...)
	if len(d.findings) > d.maxFindings {
		d.findings = d.findings[:d.maxFindings]
	}
}

// SetDone marks the scan as complete.
func (d *Dashboard) SetDone() {
	d.done = true
}

// Init implements tea.Model.
func (d *Dashboard) Init() tea.Cmd {
	return tea.Batch(d.tick(), tea.EnterAltScreen)
}

// tick schedules UI refreshes every 250ms.
func (d *Dashboard) tick() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Update implements tea.Model.
func (d *Dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			d.quitting = true
			return d, tea.Quit
		}
	case tea.WindowSizeMsg:
		d.width = msg.Width
		d.height = msg.Height
	case tickMsg:
		if d.done && d.quitting {
			return d, tea.Quit
		}
		return d, d.tick()
	}
	return d, nil
}

// View implements tea.Model.
func (d *Dashboard) View() string {
	if d.quitting {
		return "\n  Scann3r terminated. Results saved to database.\n\n"
	}

	var sections []string

	// --- Header ---
	header := titleStyle.Render("  ⚡ SCANN3R — Web Vulnerability Scanner  v1.0.0  ")
	sections = append(sections, header)

	// --- Target info ---
	targetInfo := fmt.Sprintf("  %s %s    %s %s",
		headerStyle.Render("Target:"), d.target,
		headerStyle.Render("Status:"), d.statusText())
	sections = append(sections, targetInfo)

	// --- Progress bar ---
	sections = append(sections, "  "+d.progressBar())

	// --- Stats grid ---
	statsLeft := boxStyle.Width(35).Render(d.discoveryStats())
	statsRight := boxStyle.Width(35).Render(d.requestStats())
	statsRow := lipgloss.JoinHorizontal(lipgloss.Top, "  ", statsLeft, "  ", statsRight)
	sections = append(sections, statsRow)

	// --- Findings summary ---
	sections = append(sections, "  "+d.findingsBar())

	// --- Latest findings ---
	if len(d.findings) > 0 {
		sections = append(sections, "  "+headerStyle.Render("Latest Findings:"))
		for _, f := range d.findings {
			icon := severityIcon(f.Severity)
			line := fmt.Sprintf("  %s [%s] %s → %s?%s",
				icon, strings.ToUpper(f.Type),
				truncate(f.Payload, 40),
				truncate(f.URL, 30),
				f.Parameter)
			sections = append(sections, line)
		}
	}

	// --- Log feed ---
	if len(d.logs) > 0 {
		sections = append(sections, "")
		for _, l := range d.logs {
			sections = append(sections, "  "+logStyle.Render(l))
		}
	}

	// --- Footer ---
	sections = append(sections, "")
	sections = append(sections, dimStyle.Render("  Press 'q' to stop scan"))

	return strings.Join(sections, "\n") + "\n"
}

// ---------------------------------------------------------------------------
// View helpers
// ---------------------------------------------------------------------------

func (d *Dashboard) statusText() string {
	if d.done {
		return headerStyle.Render("✓ Complete")
	}
	elapsed := time.Since(d.stats.StartedAt).Round(time.Second)
	return fmt.Sprintf("Scanning... (%s)", elapsed)
}

func (d *Dashboard) progressBar() string {
	sent := d.stats.RequestsSent.Load()
	total := d.stats.RequestsTotal.Load()
	if total == 0 {
		total = 1
	}
	pct := float64(sent) / float64(total)
	if pct > 1 {
		pct = 1
	}

	width := 40
	filled := int(pct * float64(width))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return fmt.Sprintf("%s %s%.0f%%",
		headerStyle.Render("Progress:"),
		statValueStyle.Render(bar+" "),
		pct*100)
}

func (d *Dashboard) discoveryStats() string {
	return fmt.Sprintf("%s\n%s %s\n%s %s\n%s %s\n%s %s",
		headerStyle.Render("─ Discovery ─"),
		statLabelStyle.Render("URLs Found:    "), statValueStyle.Render(fmt.Sprintf("%d", d.stats.URLsFound.Load())),
		statLabelStyle.Render("JS Files:      "), statValueStyle.Render(fmt.Sprintf("%d", d.stats.JSFilesFound.Load())),
		statLabelStyle.Render("Forms:         "), statValueStyle.Render(fmt.Sprintf("%d", d.stats.FormsFound.Load())),
		statLabelStyle.Render("Parameters:    "), statValueStyle.Render(fmt.Sprintf("%d", d.stats.ParametersFound.Load())),
	)
}

func (d *Dashboard) requestStats() string {
	return fmt.Sprintf("%s\n%s %s\n%s %s\n%s %s\n%s %s",
		headerStyle.Render("─ Requests ─"),
		statLabelStyle.Render("Sent:      "), statValueStyle.Render(fmt.Sprintf("%d / %d", d.stats.RequestsSent.Load(), d.stats.RequestsTotal.Load())),
		statLabelStyle.Render("Rate:      "), statValueStyle.Render(fmt.Sprintf("%.1f req/s", d.stats.RequestRate())),
		statLabelStyle.Render("Errors:    "), statValueStyle.Render(fmt.Sprintf("%d", d.stats.Errors.Load())),
		statLabelStyle.Render("WAF Blocks:"), statValueStyle.Render(fmt.Sprintf("%d", d.stats.WAFBlocks.Load())),
	)
}

func (d *Dashboard) findingsBar() string {
	fm := d.stats.GetFindings()
	parts := []string{headerStyle.Render("Findings:")}

	if c := fm["critical"]; c > 0 {
		parts = append(parts, criticalStyle.Render(fmt.Sprintf("🔴 CRITICAL %d", c)))
	}
	if c := fm["high"]; c > 0 {
		parts = append(parts, highStyle.Render(fmt.Sprintf("🟠 HIGH %d", c)))
	}
	if c := fm["medium"]; c > 0 {
		parts = append(parts, mediumStyle.Render(fmt.Sprintf("🟡 MEDIUM %d", c)))
	}
	if c := fm["low"]; c > 0 {
		parts = append(parts, lowStyle.Render(fmt.Sprintf("🔵 LOW %d", c)))
	}

	if len(parts) == 1 {
		parts = append(parts, dimStyle.Render("None yet"))
	}

	return strings.Join(parts, "  ")
}

func severityIcon(sev string) string {
	switch sev {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	default:
		return "⚪"
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
