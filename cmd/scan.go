package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/rheatkhs/lurah/reporter"
	"github.com/rheatkhs/lurah/scanner"
)

// scanCmd represents the scan command.
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a Laravel project for security issues",
	Long: `Runs all security scanners against the specified Laravel project:

  • Secret Scanner  — checks .env for exposed secrets (APP_DEBUG, APP_KEY)
  • PII Scanner     — checks Controllers for unmasked PII in JSON responses`,
	RunE: func(cmd *cobra.Command, args []string) error {
		banner()

		// Resolve project path to absolute
		absPath, err := filepath.Abs(projectPath)
		if err != nil {
			return fmt.Errorf("failed to resolve path: %w", err)
		}

		// Verify the path exists
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			return fmt.Errorf("project path does not exist: %s", absPath)
		}

		color.New(color.FgWhite).Printf("  Scanning: %s\n", absPath)
		fmt.Println()

		// Run all scanners
		var findings []scanner.Finding

		color.New(color.FgWhite).Print("  [1/2] ")
		color.New(color.FgCyan).Println("Running Secret Scanner...")
		secretFindings := scanner.ScanSecrets(absPath)
		findings = append(findings, secretFindings...)

		color.New(color.FgWhite).Print("  [2/2] ")
		color.New(color.FgCyan).Println("Running PII Scanner...")
		piiFindings := scanner.ScanPII(absPath)
		findings = append(findings, piiFindings...)

		// Output results
		reporter.PrintTable(findings)

		// Exit with code 1 if any CRITICAL findings
		for _, f := range findings {
			if f.Severity == scanner.CRITICAL {
				os.Exit(1)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
