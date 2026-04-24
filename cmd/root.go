package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const version = "1.0.0"

var projectPath string

// banner prints a professional CLI header with credits.
func banner() {
	dim := color.New(color.FgHiBlack)
	cyan := color.New(color.FgCyan, color.Bold)
	white := color.New(color.FgWhite, color.Bold)
	gray := color.New(color.FgHiBlack)

	fmt.Println()
	dim.Println("  ┌─────────────────────────────────────────────────┐")
	cyan.Println("  │  ██╗     ██╗   ██╗██████╗  █████╗ ██╗  ██╗    │")
	cyan.Println("  │  ██║     ██║   ██║██╔══██╗██╔══██╗██║  ██║    │")
	cyan.Println("  │  ██║     ██║   ██║██████╔╝███████║███████║    │")
	cyan.Println("  │  ██║     ██║   ██║██╔══██╗██╔══██║██╔══██║    │")
	cyan.Println("  │  ███████╗╚██████╔╝██║  ██║██║  ██║██║  ██║    │")
	cyan.Println("  │  ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    │")
	dim.Println("  ├─────────────────────────────────────────────────┤")
	white.Printf("  │  ")
	color.New(color.FgWhite).Print("Laravel Security Auditor")
	gray.Printf("              v%s", version)
	white.Println("  │")
	dim.Printf("  │  ")
	color.New(color.FgHiCyan).Print("SPBE Compliance Scanner")
	gray.Print("    github.com/rheatkhs")
	dim.Println("  │")
	dim.Println("  └─────────────────────────────────────────────────┘")
	fmt.Println()
}

// rootCmd is the base command for the Lurah CLI.
var rootCmd = &cobra.Command{
	Use:   "lurah",
	Short: "Lurah — Laravel Security Auditor for SPBE Compliance",
	Long: `Lurah is a CLI tool that audits Laravel projects for security issues
aligned with Indonesian government (SPBE) standards.

It runs 13 built-in scanners to detect exposed secrets, PII leaks,
SQL injection, XSS, mass assignment, insecure auth, and more.

  Repository:  https://github.com/rheatkhs/lurah
  Version:     ` + version,
	Run: func(cmd *cobra.Command, args []string) {
		banner()
		_ = cmd.Help()
	},
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&projectPath, "path", "p", ".", "Path to the Laravel project root")
}
