package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:          "vaultr [command] [flags]",
	Short:        "VaultR CLI",
	SilenceUsage: true,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(createCmd)

	rootCmd.AddCommand(passwordAddCmd)
	rootCmd.AddCommand(passwordRemoveCmd)

	rootCmd.AddCommand(entryListCmd)
	rootCmd.AddCommand(entrySetCmd)
	rootCmd.AddCommand(entryGetCmd)
	rootCmd.AddCommand(entryRemoveCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}
