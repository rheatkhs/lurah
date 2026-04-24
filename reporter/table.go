package reporter

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/rheatkhs/lurah/scanner"
)

// colorize returns a severity string colored for terminal output.
func colorize(s scanner.Severity) string {
	switch s {
	case scanner.CRITICAL:
		return color.New(color.FgRed, color.Bold).Sprint(string(s))
	case scanner.HIGH:
		return color.New(color.FgYellow, color.Bold).Sprint(string(s))
	case scanner.MEDIUM:
		return color.New(color.FgCyan).Sprint(string(s))
	default:
		return string(s)
	}
}

// PrintTable renders all findings as a formatted table in the terminal.
func PrintTable(findings []scanner.Finding) {
	if len(findings) == 0 {
		color.New(color.FgGreen, color.Bold).Println("\n  ✓ No security issues found. Your Laravel project looks clean!")
		fmt.Println()
		return
	}

	fmt.Println()
	color.New(color.FgWhite, color.Bold).Printf("  Found %d issue(s):\n\n", len(findings))

	table := tablewriter.NewTable(os.Stdout)
	table.Header("Severity", "File", "Recommendation")

	var critical, high, medium int

	for _, f := range findings {
		severity := colorize(f.Severity)
		fileLoc := fmt.Sprintf("%s:%d", f.File, f.Line)

		switch f.Severity {
		case scanner.CRITICAL:
			critical++
		case scanner.HIGH:
			high++
		case scanner.MEDIUM:
			medium++
		}

		table.Append(severity, fileLoc, f.Recommendation)
	}

	table.Render()

	// Summary footer
	fmt.Println()
	parts := []string{}
	if critical > 0 {
		parts = append(parts, color.RedString("%d critical", critical))
	}
	if high > 0 {
		parts = append(parts, color.YellowString("%d high", high))
	}
	if medium > 0 {
		parts = append(parts, color.CyanString("%d medium", medium))
	}
	color.New(color.Bold).Printf("  Summary: %d findings (%s)\n\n", len(findings), strings.Join(parts, ", "))
}
