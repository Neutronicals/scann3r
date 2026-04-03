// Scann3r — Asynchronous Web Vulnerability Scanner & WAF Bypasser
//
// Usage:
//
//	scann3r scan  --target https://example.com [flags]
//	scann3r report --scan-id <id> [--format html|json|md]
//	scann3r payloads
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/venom-scanner/venom/internal/config"
	"github.com/venom-scanner/venom/internal/engine"
	"github.com/venom-scanner/venom/internal/reporter"
	"github.com/venom-scanner/venom/internal/scanner/payloads"
	"github.com/venom-scanner/venom/internal/storage"
	"github.com/venom-scanner/venom/internal/ui"
)

const banner = `
 ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗██████╗ ██████╗ 
 ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║╚════██╗██╔══██╗
 ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║ █████╔╝██████╔╝
 ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║ ╚═══██╗██╔══██╗
 ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║██████╔╝██║  ██║
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝
   Asynchronous Web Vulnerability Scanner v1.0.0
`

func main() {
	rootCmd := &cobra.Command{
		Use:   "scann3r",
		Short: "Asynchronous Web Vulnerability Scanner & WAF Bypasser",
		Long:  banner + "\n  Point. Scan. Report. Intelligent vulnerability discovery with WAF bypass.\n\n  ⚠️  AUTHORIZED TESTING ONLY. Only scan targets you have explicit permission to test.",
	}

	// ─── scan command ────────────────────────────────────────────────────
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a vulnerability scan against a target",
		RunE:  runScan,
	}

	scanCmd.Flags().StringP("target", "t", "", "Target URL (required)")
	scanCmd.Flags().IntP("depth", "d", 3, "Max crawl depth")
	scanCmd.Flags().Int("crawl-threads", 20, "Concurrent crawler goroutines")
	scanCmd.Flags().Int("fuzz-threads", 30, "Concurrent fuzzer goroutines")
	scanCmd.Flags().Float64P("rate", "r", 10.0, "Max requests/sec per domain")
	scanCmd.Flags().StringP("output", "o", "", "Output report file path")
	scanCmd.Flags().StringP("format", "f", "json", "Report format: json, html, md")
	scanCmd.Flags().String("db", "scann3r.db", "SQLite database path")
	scanCmd.Flags().StringSlice("scope", nil, "Additional in-scope hostnames")
	scanCmd.Flags().Bool("no-robots", false, "Ignore robots.txt")
	scanCmd.Flags().BoolP("verbose", "v", false, "Verbose logging")
	scanCmd.Flags().Bool("headless", false, "Run without the TUI dashboard")
	scanCmd.MarkFlagRequired("target")

	// ─── report command ──────────────────────────────────────────────────
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a report from a previous scan",
		RunE:  runReport,
	}

	reportCmd.Flags().String("scan-id", "", "Scan ID to report on (required)")
	reportCmd.Flags().StringP("format", "f", "json", "Report format: json, html, md")
	reportCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	reportCmd.Flags().String("db", "scann3r.db", "SQLite database path")
	reportCmd.MarkFlagRequired("scan-id")

	// ─── payloads command ────────────────────────────────────────────────
	payloadsCmd := &cobra.Command{
		Use:   "payloads",
		Short: "List available payload categories",
		RunE:  runPayloads,
	}

	// ─── analyze command ─────────────────────────────────────────────────
	analyzeCmd := &cobra.Command{
		Use:   "analyze",
		Short: "Generate an interactive analytics dashboard from scan data",
		RunE:  runAnalyze,
	}

	analyzeCmd.Flags().String("scan-id", "", "Analyze a specific scan (default: all scans)")
	analyzeCmd.Flags().StringP("output", "o", "scann3r_analysis.html", "Output HTML file path")
	analyzeCmd.Flags().String("db", "scann3r.db", "SQLite database path")

	rootCmd.AddCommand(scanCmd, reportCmd, payloadsCmd, analyzeCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// ─── scan handler ────────────────────────────────────────────────────────────

func runScan(cmd *cobra.Command, args []string) error {
	fmt.Print(banner)
	fmt.Println("  ⚠️  AUTHORIZED TESTING ONLY")
	fmt.Println()

	// Build config from flags
	cfg := config.DefaultConfig()
	cfg.Target, _ = cmd.Flags().GetString("target")
	cfg.MaxDepth, _ = cmd.Flags().GetInt("depth")
	cfg.CrawlThreads, _ = cmd.Flags().GetInt("crawl-threads")
	cfg.FuzzThreads, _ = cmd.Flags().GetInt("fuzz-threads")
	cfg.RatePerSec, _ = cmd.Flags().GetFloat64("rate")
	cfg.OutputFile, _ = cmd.Flags().GetString("output")
	cfg.OutputFormat, _ = cmd.Flags().GetString("format")
	cfg.DBPath, _ = cmd.Flags().GetString("db")
	cfg.Verbose, _ = cmd.Flags().GetBool("verbose")

	scope, _ := cmd.Flags().GetStringSlice("scope")
	cfg.Scope = append(cfg.Scope, scope...)

	noRobots, _ := cmd.Flags().GetBool("no-robots")
	cfg.RespectRobots = !noRobots

	headless, _ := cmd.Flags().GetBool("headless")

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	// Open database
	db, err := storage.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	defer db.Close()

	// Create engine
	eng, err := engine.New(cfg, db)
	if err != nil {
		return err
	}

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n\n  Shutting down gracefully... (press Ctrl+C again to force)")
		cancel()
	}()

	if headless {
		// Run without TUI
		fmt.Printf("  Target:  %s\n", cfg.Target)
		fmt.Printf("  Scan ID: %s\n", cfg.ScanID)
		fmt.Printf("  DB:      %s\n\n", cfg.DBPath)

		if err := eng.Run(ctx); err != nil {
			return err
		}
	} else {
		// Run with TUI dashboard
		dashboard := ui.NewDashboard(eng.Stats(), cfg.Target, cfg.ScanID)
		eng.SetDashboard(dashboard)

		// Run the engine in a background goroutine
		go func() {
			if err := eng.Run(ctx); err != nil {
				dashboard.AddLog(fmt.Sprintf("Engine error: %v", err))
			}
			dashboard.SetDone()
		}()

		// Run the TUI (blocks until user quits)
		p := tea.NewProgram(dashboard)
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
		cancel() // ensure engine stops if user quits TUI
	}

	// Generate report if output file specified
	if cfg.OutputFile != "" {
		rep := reporter.NewReporter(db, cfg.ScanID)
		if err := rep.Generate(context.Background(), cfg.OutputFormat, cfg.OutputFile); err != nil {
			return fmt.Errorf("report generation error: %w", err)
		}
		fmt.Printf("\n  Report saved to: %s\n", cfg.OutputFile)
	}

	return nil
}

// ─── report handler ──────────────────────────────────────────────────────────

func runReport(cmd *cobra.Command, args []string) error {
	scanID, _ := cmd.Flags().GetString("scan-id")
	format, _ := cmd.Flags().GetString("format")
	output, _ := cmd.Flags().GetString("output")
	dbPath, _ := cmd.Flags().GetString("db")

	db, err := storage.Open(dbPath)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	defer db.Close()

	rep := reporter.NewReporter(db, scanID)
	return rep.Generate(context.Background(), format, output)
}

// ─── payloads handler ────────────────────────────────────────────────────────

func runPayloads(cmd *cobra.Command, args []string) error {
	all, err := payloads.LoadAll()
	if err != nil {
		return err
	}

	fmt.Println("\n  Available Payload Categories:")
	fmt.Println("  " + strings.Repeat("─", 50))

	for cat, pf := range all {
		fmt.Printf("  %-15s  %s  (%d payloads)  [%s]\n",
			cat, pf.Name, len(pf.Payloads), pf.Severity)
	}
	fmt.Println()

	return nil
}

// ─── analyze handler ─────────────────────────────────────────────────────────

func runAnalyze(cmd *cobra.Command, args []string) error {
	fmt.Print(banner)

	scanID, _ := cmd.Flags().GetString("scan-id")
	output, _ := cmd.Flags().GetString("output")
	dbPath, _ := cmd.Flags().GetString("db")

	db, err := storage.Open(dbPath)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	defer db.Close()

	fmt.Printf("  📊 Generating analytics dashboard...\n")
	fmt.Printf("  Database: %s\n", dbPath)
	if scanID != "" {
		fmt.Printf("  Scan ID:  %s\n", scanID)
	} else {
		fmt.Printf("  Scope:    All scans\n")
	}

	dash := reporter.NewAnalyticsDashboard(db, scanID)
	if err := dash.Generate(context.Background(), output); err != nil {
		return err
	}

	fmt.Printf("\n  ✅ Dashboard saved to: %s\n", output)
	fmt.Printf("  Open it in your browser to explore the data.\n\n")

	return nil
}

func init() {
	log.SetFlags(log.Ltime | log.Lshortfile)
}
