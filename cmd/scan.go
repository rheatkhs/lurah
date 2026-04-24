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
	outputFormat string
	minSeverity  string
	autoFix      bool
)

// scanCmd represents the scan command.
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a Laravel project for security issues",
	Long: `Runs all security scanners against the specified Laravel project:

  - Secret Scanner     — checks .env for exposed secrets (APP_DEBUG, APP_KEY)
  - PII Scanner        — checks Controllers for unmasked PII in JSON responses
  - SQL Injection      — detects raw queries with variable interpolation
  - CSRF Scanner       — flags overly broad CSRF exclusions
  - Middleware Scanner  — verifies auth/throttle on sensitive routes
  - Dependency Scanner  — audits composer.lock for vulnerable packages
  - Config Scanner     — checks config/ for hardcoded secrets and debug flags
  - Env Diff           — compares .env against .env.example`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Resolve project path to absolute
		absPath, err := filepath.Abs(projectPath)
		if err != nil {
			return fmt.Errorf("failed to resolve path: %w", err)
		}

		// Verify the path exists
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			return fmt.Errorf("project path does not exist: %s", absPath)
		}

		// Load config
		cfg := scanner.LoadConfig(absPath)

		// Override min severity from flag if set
		if minSeverity != "" {
			cfg.MinSeverity = strings.ToUpper(minSeverity)
		}

		// Only show banner for table format
		if outputFormat == "table" || outputFormat == "" {
			banner()
			color.New(color.FgWhite).Printf("  Scanning: %s\n", absPath)
			fmt.Println()
		}

		// Run all enabled scanners
		var findings []scanner.Finding
		scannerCount := 0
		totalScanners := countEnabled(cfg)

		if cfg.Scanners.Secret {
			scannerCount++
			printProgress(scannerCount, totalScanners, "Secret Scanner")
			findings = append(findings, scanner.ScanSecrets(absPath)...)
		}

		if cfg.Scanners.PII {
			scannerCount++
			printProgress(scannerCount, totalScanners, "PII Scanner")
			findings = append(findings, scanner.ScanPII(absPath)...)
		}

		if cfg.Scanners.SQLi {
			scannerCount++
			printProgress(scannerCount, totalScanners, "SQL Injection Scanner")
			findings = append(findings, scanner.ScanSQLInjection(absPath)...)
		}

		if cfg.Scanners.CSRF {
			scannerCount++
			printProgress(scannerCount, totalScanners, "CSRF Scanner")
			findings = append(findings, scanner.ScanCSRF(absPath)...)
		}

		if cfg.Scanners.Middleware {
			scannerCount++
			printProgress(scannerCount, totalScanners, "Middleware Scanner")
			findings = append(findings, scanner.ScanMiddleware(absPath)...)
		}

		if cfg.Scanners.Dependency {
			scannerCount++
			printProgress(scannerCount, totalScanners, "Dependency Scanner")
			findings = append(findings, scanner.ScanDependencies(absPath)...)
		}

		if cfg.Scanners.Config {
			scannerCount++
			printProgress(scannerCount, totalScanners, "Config Scanner")
			findings = append(findings, scanner.ScanConfig(absPath)...)
		}

		if cfg.Scanners.EnvDiff {
			scannerCount++
			printProgress(scannerCount, totalScanners, "Env Diff Scanner")
			findings = append(findings, scanner.ScanEnvDiff(absPath)...)
		}

		// Apply severity filter
		if cfg.MinSeverity != "" {
			findings = scanner.FilterBySeverity(findings, cfg.MinSeverity)
		}

		// Auto-fix if requested
		if autoFix {
			fixCount, messages := scanner.ApplyFixes(absPath, findings)
			if fixCount > 0 && (outputFormat == "table" || outputFormat == "") {
				fmt.Println()
				color.New(color.FgGreen, color.Bold).Printf("  Auto-fixed %d issue(s):\n", fixCount)
				for _, msg := range messages {
					color.New(color.FgGreen).Printf("    - %s\n", msg)
				}
				fmt.Println()

				// Re-scan after fixes
				color.New(color.FgWhite).Println("  Re-scanning after fixes...")
				fmt.Println()
				findings = nil
				if cfg.Scanners.Secret {
					findings = append(findings, scanner.ScanSecrets(absPath)...)
				}
				if cfg.Scanners.PII {
					findings = append(findings, scanner.ScanPII(absPath)...)
				}
				if cfg.Scanners.SQLi {
					findings = append(findings, scanner.ScanSQLInjection(absPath)...)
				}
				if cfg.Scanners.CSRF {
					findings = append(findings, scanner.ScanCSRF(absPath)...)
				}
				if cfg.Scanners.Middleware {
					findings = append(findings, scanner.ScanMiddleware(absPath)...)
				}
				if cfg.Scanners.Dependency {
					findings = append(findings, scanner.ScanDependencies(absPath)...)
				}
				if cfg.Scanners.Config {
					findings = append(findings, scanner.ScanConfig(absPath)...)
				}
				if cfg.Scanners.EnvDiff {
					findings = append(findings, scanner.ScanEnvDiff(absPath)...)
				}
				if cfg.MinSeverity != "" {
					findings = scanner.FilterBySeverity(findings, cfg.MinSeverity)
				}
			}
		}

		// Output results in the requested format
		switch strings.ToLower(outputFormat) {
		case "json":
			reporter.PrintJSON(findings, absPath)
		case "sarif":
			reporter.PrintSARIF(findings)
		default:
			reporter.PrintTable(findings)
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
	color.New(color.FgWhite).Printf("  [%d/%d] ", current, total)
	color.New(color.FgCyan).Println("Running " + name + "...")
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

		// Simple polling-based watcher
		lastModTime := time.Time{}
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		// Initial scan
		runScan(absPath)
		lastModTime = getLatestModTime(absPath)

		for range ticker.C {
			currentModTime := getLatestModTime(absPath)
			if currentModTime.After(lastModTime) {
				lastModTime = currentModTime
				color.New(color.FgYellow).Println("\n  --- Changes detected, re-scanning... ---")
				fmt.Println()
				runScan(absPath)
			}
		}

		return nil
	},
}

func runScan(absPath string) {
	cfg := scanner.LoadConfig(absPath)
	var findings []scanner.Finding

	if cfg.Scanners.Secret {
		findings = append(findings, scanner.ScanSecrets(absPath)...)
	}
	if cfg.Scanners.PII {
		findings = append(findings, scanner.ScanPII(absPath)...)
	}
	if cfg.Scanners.SQLi {
		findings = append(findings, scanner.ScanSQLInjection(absPath)...)
	}
	if cfg.Scanners.CSRF {
		findings = append(findings, scanner.ScanCSRF(absPath)...)
	}
	if cfg.Scanners.Middleware {
		findings = append(findings, scanner.ScanMiddleware(absPath)...)
	}
	if cfg.Scanners.Dependency {
		findings = append(findings, scanner.ScanDependencies(absPath)...)
	}
	if cfg.Scanners.Config {
		findings = append(findings, scanner.ScanConfig(absPath)...)
	}
	if cfg.Scanners.EnvDiff {
		findings = append(findings, scanner.ScanEnvDiff(absPath)...)
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
	}

	// Also check .env directly
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

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(watchCmd)
}
