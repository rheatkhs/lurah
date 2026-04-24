package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var projectPath string

// banner prints the Lurah ASCII art header.
func banner() {
	cyan := color.New(color.FgCyan, color.Bold)
	white := color.New(color.FgWhite)

	cyan.Println(`
  ██╗     ██╗   ██╗██████╗  █████╗ ██╗  ██╗
  ██║     ██║   ██║██╔══██╗██╔══██╗██║  ██║
  ██║     ██║   ██║██████╔╝███████║███████║
  ██║     ██║   ██║██╔══██╗██╔══██║██╔══██║
  ███████╗╚██████╔╝██║  ██║██║  ██║██║  ██║
  ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝`)
	white.Println("  Laravel Security Auditor for SPBE Compliance")
	fmt.Println()
}

// rootCmd is the base command for the Lurah CLI.
var rootCmd = &cobra.Command{
	Use:   "lurah",
	Short: "Lurah — Laravel Security Auditor",
	Long: `Lurah is a CLI tool that audits Laravel projects for security issues
aligned with Indonesian government (SPBE) standards.

It scans for exposed secrets, PII leaks in API responses, and other
common vulnerabilities.`,
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
