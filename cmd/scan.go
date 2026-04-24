package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/rheatkhs/lurah/reporter"
	"github.com/rheatkhs/lurah/scanner"
)

var (
	outputFormat   string
	minSeverity    string
	autoFix        bool
	baselineCreate bool
	baselineUse    bool
	htmlOutput     string
)

// scanCmd represents the scan command.
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a Laravel project for security issues",
	Long: `Runs all security scanners against the specified Laravel project:

  - Secret Scanner       — checks .env for exposed secrets
  - PII Scanner          — checks Controllers for unmasked PII
  - SQL Injection        — detects raw queries with variable interpolation
  - CSRF Scanner         — flags overly broad CSRF exclusions
  - Middleware Scanner   — verifies auth/throttle on sensitive routes
  - Dependency Scanner   — audits composer.lock for vulnerable packages
  - Config Scanner       — checks config/ for hardcoded secrets
  - Env Diff             — compares .env against .env.example
  - XSS Scanner          — detects unescaped Blade output
  - Mass Assignment      — flags models without $fillable/$guarded
  - File Upload          — detects uploads without MIME validation
  - Auth Scanner         — audits authentication and session config
  - Advisory Scanner     — checks packages against Packagist CVE database
  - Custom Rules         — runs user-defined rules from .lurah.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		absPath, err := filepath.Abs(projectPath)
		if err != nil {
			return fmt.Errorf("failed to resolve path: %w", err)
		}

		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			return fmt.Errorf("project path does not exist: %s", absPath)
		}

		cfg := scanner.LoadConfig(absPath)

		if minSeverity != "" {
			cfg.MinSeverity = strings.ToUpper(minSeverity)
		}

		isTable := outputFormat == "" || outputFormat == "table"

		if isTable {
			banner()
			dim := color.New(color.FgHiBlack)
			color.New(color.FgWhite, color.Bold).Print("  Target: ")
			color.New(color.FgHiCyan).Println(absPath)
			dim.Println("  ─── Scanning ────────────────────────────────────")
			fmt.Println()
		}

		var findings []scanner.Finding
		scannerCount := 0
		totalScanners := countEnabled(cfg)

		type scannerEntry struct {
			name    string
			enabled bool
			fn      func() []scanner.Finding
		}

		scanners := []scannerEntry{
			{"Secret Scanner", cfg.Scanners.Secret, func() []scanner.Finding { return scanner.ScanSecrets(absPath) }},
			{"PII Scanner", cfg.Scanners.PII, func() []scanner.Finding { return scanner.ScanPII(absPath) }},
			{"SQL Injection Scanner", cfg.Scanners.SQLi, func() []scanner.Finding { return scanner.ScanSQLInjection(absPath) }},
			{"CSRF Scanner", cfg.Scanners.CSRF, func() []scanner.Finding { return scanner.ScanCSRF(absPath) }},
			{"Middleware Scanner", cfg.Scanners.Middleware, func() []scanner.Finding { return scanner.ScanMiddleware(absPath) }},
			{"Dependency Scanner", cfg.Scanners.Dependency, func() []scanner.Finding { return scanner.ScanDependencies(absPath) }},
			{"Config Scanner", cfg.Scanners.Config, func() []scanner.Finding { return scanner.ScanConfig(absPath) }},
			{"Env Diff Scanner", cfg.Scanners.EnvDiff, func() []scanner.Finding { return scanner.ScanEnvDiff(absPath) }},
			{"XSS Scanner", cfg.Scanners.XSS, func() []scanner.Finding { return scanner.ScanXSS(absPath) }},
			{"Mass Assignment Scanner", cfg.Scanners.MassAssignment, func() []scanner.Finding { return scanner.ScanMassAssignment(absPath) }},
			{"File Upload Scanner", cfg.Scanners.FileUpload, func() []scanner.Finding { return scanner.ScanFileUpload(absPath) }},
			{"Auth Scanner", cfg.Scanners.Auth, func() []scanner.Finding { return scanner.ScanAuth(absPath) }},
			{"Advisory Scanner", cfg.Scanners.Advisory, func() []scanner.Finding { return scanner.ScanAdvisories(absPath) }},
		}

		for _, s := range scanners {
			if !s.enabled {
				continue
			}
			scannerCount++
			printProgress(scannerCount, totalScanners, s.name)
			findings = append(findings, s.fn()...)
		}

		// Run custom rules
		if len(cfg.CustomRules) > 0 {
			if isTable {
				color.New(color.FgWhite).Print("  [+] ")
				color.New(color.FgCyan).Printf("Running %d custom rule(s)...\n", len(cfg.CustomRules))
			}
			findings = append(findings, scanner.ScanCustomRules(absPath, cfg.CustomRules)...)
		}

		// Apply severity filter
		if cfg.MinSeverity != "" {
			findings = scanner.FilterBySeverity(findings, cfg.MinSeverity)
		}

		// Apply baseline filter
		if baselineUse {
			baseline, err := scanner.LoadBaseline(absPath)
			if err == nil {
				before := len(findings)
				findings = scanner.ApplyBaseline(findings, baseline)
				if isTable {
					suppressed := before - len(findings)
					if suppressed > 0 {
						color.New(color.FgWhite).Printf("\n  Baseline: %d known issue(s) suppressed\n", suppressed)
					}
				}
			}
		}

		// Auto-fix if requested
		if autoFix {
			fixCount, messages := scanner.ApplyFixes(absPath, findings)
			if fixCount > 0 && isTable {
				fmt.Println()
				color.New(color.FgGreen, color.Bold).Printf("  Auto-fixed %d issue(s):\n", fixCount)
				for _, msg := range messages {
					color.New(color.FgGreen).Printf("    - %s\n", msg)
				}
				fmt.Println()
				color.New(color.FgWhite).Println("  Re-scanning after fixes...")
				fmt.Println()

				// Re-scan after fixes
				findings = nil
				for _, s := range scanners {
					if s.enabled {
						findings = append(findings, s.fn()...)
					}
				}
				if len(cfg.CustomRules) > 0 {
					findings = append(findings, scanner.ScanCustomRules(absPath, cfg.CustomRules)...)
				}
				if cfg.MinSeverity != "" {
					findings = scanner.FilterBySeverity(findings, cfg.MinSeverity)
				}
			}
		}

		// Save baseline if requested
		if baselineCreate {
			if err := scanner.SaveBaseline(absPath, findings); err != nil {
				return fmt.Errorf("failed to save baseline: %w", err)
			}
			if isTable {
				color.New(color.FgGreen, color.Bold).Printf("\n  Baseline saved: %d finding(s) recorded in .lurah-baseline.json\n", len(findings))
			}
		}

		// Output results
		switch strings.ToLower(outputFormat) {
		case "json":
			reporter.PrintJSON(findings, absPath)
		case "sarif":
			reporter.PrintSARIF(findings)
		default:
			reporter.PrintTable(findings)
		}

		// Generate HTML report if requested
		if htmlOutput != "" {
			htmlPath := htmlOutput
			if !filepath.IsAbs(htmlPath) {
				htmlPath = filepath.Join(absPath, htmlPath)
			}
			if err := reporter.PrintHTML(findings, absPath, htmlPath); err != nil {
				return fmt.Errorf("failed to write HTML report: %w", err)
			}
			if isTable {
				color.New(color.FgGreen).Printf("  HTML report saved: %s\n\n", htmlPath)
			}
		}

		// Exit with code 1 if any CRITICAL findings
		for _, f := range findings {
			if f.Severity == scanner.CRITICAL {
				os.Exit(1)
			}
		}

		return nil
	},
}

func printProgress(current, total int, name string) {
	if outputFormat != "" && outputFormat != "table" {
		return
	}
	dim := color.New(color.FgHiBlack)
	dim.Printf("  %2d/%d ", current, total)
	color.New(color.FgHiBlack).Print("→ ")
	color.New(color.FgWhite).Println(name)
}

func countEnabled(cfg scanner.LurahConfig) int {
	count := 0
	if cfg.Scanners.Secret {
		count++
	}
	if cfg.Scanners.PII {
		count++
	}
	if cfg.Scanners.SQLi {
		count++
	}
	if cfg.Scanners.CSRF {
		count++
	}
	if cfg.Scanners.Middleware {
		count++
	}
	if cfg.Scanners.Dependency {
		count++
	}
	if cfg.Scanners.Config {
		count++
	}
	if cfg.Scanners.EnvDiff {
		count++
	}
	if cfg.Scanners.XSS {
		count++
	}
	if cfg.Scanners.MassAssignment {
		count++
	}
	if cfg.Scanners.FileUpload {
		count++
	}
	if cfg.Scanners.Auth {
		count++
	}
	if cfg.Scanners.Advisory {
		count++
	}
	return count
}

// watchCmd represents the watch command.
var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch for file changes and re-scan automatically",
	Long: `Continuously monitors the Laravel project for file changes and
triggers a re-scan whenever a PHP, .env, or config file is modified.

Press Ctrl+C to stop watching.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		banner()

		absPath, err := filepath.Abs(projectPath)
		if err != nil {
			return fmt.Errorf("failed to resolve path: %w", err)
		}

		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			return fmt.Errorf("project path does not exist: %s", absPath)
		}

		color.New(color.FgCyan, color.Bold).Printf("  Watching: %s\n", absPath)
		color.New(color.FgWhite).Println("  Press Ctrl+C to stop.")
		fmt.Println()

		lastModTime := time.Time{}
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		runWatchScan(absPath)
		lastModTime = getLatestModTime(absPath)

		for range ticker.C {
			currentModTime := getLatestModTime(absPath)
			if currentModTime.After(lastModTime) {
				lastModTime = currentModTime
				color.New(color.FgYellow).Println("\n  --- Changes detected, re-scanning... ---")
				fmt.Println()
				runWatchScan(absPath)
			}
		}

		return nil
	},
}

func runWatchScan(absPath string) {
	cfg := scanner.LoadConfig(absPath)
	var findings []scanner.Finding

	type scannerEntry struct {
		enabled bool
		fn      func() []scanner.Finding
	}

	scanners := []scannerEntry{
		{cfg.Scanners.Secret, func() []scanner.Finding { return scanner.ScanSecrets(absPath) }},
		{cfg.Scanners.PII, func() []scanner.Finding { return scanner.ScanPII(absPath) }},
		{cfg.Scanners.SQLi, func() []scanner.Finding { return scanner.ScanSQLInjection(absPath) }},
		{cfg.Scanners.CSRF, func() []scanner.Finding { return scanner.ScanCSRF(absPath) }},
		{cfg.Scanners.Middleware, func() []scanner.Finding { return scanner.ScanMiddleware(absPath) }},
		{cfg.Scanners.Dependency, func() []scanner.Finding { return scanner.ScanDependencies(absPath) }},
		{cfg.Scanners.Config, func() []scanner.Finding { return scanner.ScanConfig(absPath) }},
		{cfg.Scanners.EnvDiff, func() []scanner.Finding { return scanner.ScanEnvDiff(absPath) }},
		{cfg.Scanners.XSS, func() []scanner.Finding { return scanner.ScanXSS(absPath) }},
		{cfg.Scanners.MassAssignment, func() []scanner.Finding { return scanner.ScanMassAssignment(absPath) }},
		{cfg.Scanners.FileUpload, func() []scanner.Finding { return scanner.ScanFileUpload(absPath) }},
		{cfg.Scanners.Auth, func() []scanner.Finding { return scanner.ScanAuth(absPath) }},
		{cfg.Scanners.Advisory, func() []scanner.Finding { return scanner.ScanAdvisories(absPath) }},
	}

	for _, s := range scanners {
		if s.enabled {
			findings = append(findings, s.fn()...)
		}
	}

	if len(cfg.CustomRules) > 0 {
		findings = append(findings, scanner.ScanCustomRules(absPath, cfg.CustomRules)...)
	}

	if cfg.MinSeverity != "" {
		findings = scanner.FilterBySeverity(findings, cfg.MinSeverity)
	}

	reporter.PrintTable(findings)
}

func getLatestModTime(projectPath string) time.Time {
	var latest time.Time

	watchDirs := []string{
		filepath.Join(projectPath, "app"),
		filepath.Join(projectPath, "config"),
		filepath.Join(projectPath, "routes"),
		filepath.Join(projectPath, "resources"),
	}

	if info, err := os.Stat(filepath.Join(projectPath, ".env")); err == nil {
		if info.ModTime().After(latest) {
			latest = info.ModTime()
		}
	}

	for _, dir := range watchDirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(info.Name()))
			if ext == ".php" || ext == ".env" || ext == ".yaml" || ext == ".yml" {
				if info.ModTime().After(latest) {
					latest = info.ModTime()
				}
			}
			return nil
		})
	}

	return latest
}

func init() {
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json, sarif")
	scanCmd.Flags().StringVar(&minSeverity, "min-severity", "", "Minimum severity to show: MEDIUM, HIGH, CRITICAL")
	scanCmd.Flags().BoolVar(&autoFix, "fix", false, "Auto-fix simple issues (e.g., APP_DEBUG=true)")
	scanCmd.Flags().BoolVar(&baselineCreate, "baseline-create", false, "Save current findings as baseline")
	scanCmd.Flags().BoolVar(&baselineUse, "baseline", false, "Only show findings not in baseline")
	scanCmd.Flags().StringVar(&htmlOutput, "html", "", "Generate HTML report to specified file path")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(watchCmd)
}
