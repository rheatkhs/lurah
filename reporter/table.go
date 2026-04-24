package reporter

import (
	"fmt"
	"os"
	"strings"
	"time"

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

// severityIcon returns a status icon for the severity level.
func severityIcon(s scanner.Severity) string {
	switch s {
	case scanner.CRITICAL:
		return color.New(color.FgRed, color.Bold).Sprint("■")
	case scanner.HIGH:
		return color.New(color.FgYellow, color.Bold).Sprint("■")
	case scanner.MEDIUM:
		return color.New(color.FgCyan).Sprint("■")
	default:
		return "■"
	}
}

// PrintTable renders all findings as a formatted table in the terminal.
func PrintTable(findings []scanner.Finding) {
	dim := color.New(color.FgHiBlack)

	if len(findings) == 0 {
		fmt.Println()
		color.New(color.FgGreen, color.Bold).Println("  ✓ No security issues found. Your Laravel project looks clean!")
		dim.Println("  ─────────────────────────────────────────────────")
		printFooterCredit()
		return
	}

	fmt.Println()
	dim.Println("  ─── Scan Results ────────────────────────────────")
	fmt.Println()

	var critical, high, medium int

	table := tablewriter.NewTable(os.Stdout)
	table.Header("", "Severity", "File", "Recommendation")

	for _, f := range findings {
		icon := severityIcon(f.Severity)
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

		table.Append(icon, severity, fileLoc, f.Recommendation)
	}

	table.Render()

	// Summary bar
	fmt.Println()
	dim.Print("  ─── Summary ")
	dim.Println("────────────────────────────────────")
	fmt.Println()

	// Severity breakdown with visual bars
	total := len(findings)
	if critical > 0 {
		bar := strings.Repeat("█", critical)
		color.New(color.FgRed, color.Bold).Printf("    CRITICAL  %s %d\n", bar, critical)
	}
	if high > 0 {
		bar := strings.Repeat("█", high)
		color.New(color.FgYellow, color.Bold).Printf("    HIGH      %s %d\n", bar, high)
	}
	if medium > 0 {
		bar := strings.Repeat("█", medium)
		color.New(color.FgCyan).Printf("    MEDIUM    %s %d\n", bar, medium)
	}

	fmt.Println()
	color.New(color.FgWhite, color.Bold).Printf("    Total: %d finding(s)", total)
	if critical > 0 {
		color.New(color.FgRed).Print("  ← action required")
	}
	fmt.Println()

	dim.Println()
	dim.Println("  ─────────────────────────────────────────────────")
	printFooterCredit()
}

func printFooterCredit() {
	dim := color.New(color.FgHiBlack)
	dim.Printf("  Lurah v1.0.0 | %s | github.com/rheatkhs\n", time.Now().Format("2006-01-02 15:04"))
	fmt.Println()
}
