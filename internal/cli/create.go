package cli

import (
	"errors"
	"fmt"
	"vaultr/internal/vault"

	"github.com/spf13/cobra"
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new empty vault file",
	RunE: func(cmd *cobra.Command, args []string) error {
		if 0 == len(flagPath) {
			return errors.New("--path is required")
		}

		if 8 > len(flagPassword) {
			return errors.New("--password must be at least 8 characters")
		}

		var err error
		v := vault.NewVault(flagPath)

		if err = v.Initialize(); nil != err {
			return err
		}

		if err = v.AddPassword(flagPassword); nil != err {
			return err
		}

		if err = v.Write(); nil != err {
			return err
		}

		fmt.Println("Vault initialized successfully.")
		return nil
	},
}

func init() {
	createCmd.Flags().StringVar(&flagPath, "path", "", "Path to vault file")
	createCmd.Flags().StringVar(&flagPassword, "password", "", "Vault password (min 8 chars)")

	vault.Die(createCmd.MarkFlagRequired("path"))
	vault.Die(createCmd.MarkFlagRequired("password"))
}
