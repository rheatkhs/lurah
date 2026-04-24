package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/rheatkhs/lurah/scanner"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a .lurah.yaml configuration file",
	Long: `Creates a .lurah.yaml configuration file in the specified project directory
with default settings. You can customize which scanners to enable, set minimum
severity thresholds, and define exclude paths.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		banner()

		absPath, err := filepath.Abs(projectPath)
		if err != nil {
			return fmt.Errorf("failed to resolve path: %w", err)
		}

		configPath := filepath.Join(absPath, ".lurah.yaml")
		if _, err := os.Stat(configPath); err == nil {
			color.New(color.FgYellow).Printf("  Config already exists: %s\n", configPath)
			color.New(color.FgWhite).Println("  Use --force to overwrite.")
			return nil
		}

		cfg := scanner.DefaultConfig()
		if err := scanner.WriteConfig(absPath, cfg); err != nil {
			return fmt.Errorf("failed to write config: %w", err)
		}

		color.New(color.FgGreen, color.Bold).Printf("  Created: %s\n\n", configPath)
		color.New(color.FgWhite).Println("  Edit this file to customize scanner behavior.")
		fmt.Println()

		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
