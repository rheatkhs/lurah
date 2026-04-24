package cmd

import (
	"fmt"

	"github.com/rheatkhs/lurah/web"
	"github.com/spf13/cobra"
)

var port int

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Launch the graphical web dashboard",
	RunE: func(cmd *cobra.Command, args []string) error {
		banner()
		
		server := web.NewServer(port)
		fmt.Printf("  [>] Preparing Lurah Dashboard on port %d...\n", port)
		return server.Start()
	},
}

func init() {
	webCmd.Flags().IntVarP(&port, "port", "P", 9999, "Port to run the dashboard on")
	rootCmd.AddCommand(webCmd)
}
