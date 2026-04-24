package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

const version = "1.0.0"

var (
	projectPath   string
	bannerPrinted bool
)

// banner prints a professional CLI header with credits.
func banner() {
	if bannerPrinted {
		return
	}
	bannerPrinted = true

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

// menuItem represents an interactive menu option.
type menuItem struct {
	Label       string
	Description string
	Icon        string
}

func (m menuItem) String() string {
	return m.Label
}

// showInteractiveMenu displays a selectable menu and returns the user's choice.
func showInteractiveMenu() (string, error) {
	items := []menuItem{
		{Label: "Scan Project", Description: "Run all security scanners on a Laravel project", Icon: "[ > ]"},
		{Label: "Scan (JSON Output)", Description: "Run scan with JSON output format", Icon: "[ { } ]"},
		{Label: "Scan (HTML Report)", Description: "Run scan and generate HTML report", Icon: "[ < > ]"},
		{Label: "Watch Mode", Description: "Watch for file changes and re-scan automatically", Icon: "[ ~ ]"},
		{Label: "Initialize Config", Description: "Create a .lurah.yaml configuration file", Icon: "[ + ]"},
		{Label: "Create Baseline", Description: "Save current findings as baseline", Icon: "[ = ]"},
		{Label: "Help", Description: "Show help and available commands", Icon: "[ ? ]"},
		{Label: "Exit", Description: "Exit Lurah", Icon: "[ x ]"},
	}

	templates := &promptui.SelectTemplates{
		Label:    "  {{ . | cyan | bold }}",
		Active:   "  {{ `>` | cyan | bold }} {{ .Icon | cyan }}  {{ .Label | cyan | bold }}   {{ `—` | faint }} {{ .Description | faint }}",
		Inactive: "    {{ .Icon | faint }}  {{ .Label }}   {{ `—` | faint }} {{ .Description | faint }}",
		Selected: "  {{ `*` | green | bold }} {{ .Label | green | bold }}",
	}

	prompt := promptui.Select{
		Label:     "Select an action:",
		Items:     items,
		Templates: templates,
		Size:      8,
		HideHelp:  true,
	}

	idx, _, err := prompt.Run()
	if err != nil {
		return "", err
	}

	return items[idx].Label, nil
}

// promptForPath asks the user for the project root directory.
func promptForPath() (string, error) {
	color.New(color.FgHiBlack).Println("  ─── Target Configuration ────────────────────────")
	fmt.Println()

	prompt := promptui.Prompt{
		Label: "Project directory",
		Templates: &promptui.PromptTemplates{
			Prompt:  "  {{ `?` | cyan }} {{ . | bold }} {{ `|` | faint }} ",
			Valid:   "  {{ `?` | cyan }} {{ . | bold }} {{ `|` | faint }} ",
			Invalid: "  {{ `?` | red }} {{ . | bold }} {{ `|` | faint }} ",
			Success: "  {{ `*` | green | bold }} {{ `Target path set to` | faint }} {{ . | cyan | bold }}\n",
		},
	}
	return prompt.Run()
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

		choice, err := showInteractiveMenu()
		if err != nil {
			// User pressed Ctrl+C or interrupted
			fmt.Println()
			os.Exit(0)
		}

		fmt.Println()

		switch choice {
		case "Scan Project":
			path, err := promptForPath()
			if err != nil {
				return
			}
			projectPath = path
			scanCmd.Flags().Set("format", "table")
			scanCmd.RunE(cmd, args)

		case "Scan (JSON Output)":
			path, err := promptForPath()
			if err != nil {
				return
			}
			projectPath = path
			scanCmd.Flags().Set("format", "json")
			scanCmd.RunE(cmd, args)

		case "Scan (HTML Report)":
			path, err := promptForPath()
			if err != nil {
				return
			}
			projectPath = path
			
			htmlPrompt := promptui.Prompt{
				Label: "Report filename",
				Templates: &promptui.PromptTemplates{
					Prompt:  "  {{ `?` | cyan }} {{ . | bold }} {{ `|` | faint }} ",
					Valid:   "  {{ `?` | cyan }} {{ . | bold }} {{ `|` | faint }} ",
					Invalid: "  {{ `?` | red }} {{ . | bold }} {{ `|` | faint }} ",
					Success: "  {{ `*` | green | bold }} {{ `Report saved to` | faint }} {{ . | cyan | bold }}\n",
				},
			}
			htmlPath, err := htmlPrompt.Run()
			if err != nil {
				return
			}
			scanCmd.Flags().Set("html", htmlPath)
			scanCmd.RunE(cmd, args)

		case "Watch Mode":
			path, err := promptForPath()
			if err != nil {
				return
			}
			projectPath = path
			watchCmd.RunE(cmd, args)

		case "Initialize Config":
			path, err := promptForPath()
			if err != nil {
				return
			}
			projectPath = path
			initCmd.RunE(cmd, args)

		case "Create Baseline":
			path, err := promptForPath()
			if err != nil {
				return
			}
			projectPath = path
			scanCmd.Flags().Set("baseline-create", "true")
			scanCmd.RunE(cmd, args)

		case "Help":
			cmd.Help()

		case "Exit":
			color.New(color.FgHiBlack).Println("  Goodbye!")
			fmt.Println()
		}
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
