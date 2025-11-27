package cli

import (
	"errors"
	"fmt"
	"vaultr/internal/vault"

	"github.com/spf13/cobra"
)

var passwordRemoveCmd = &cobra.Command{
	Use:   "password:remove",
	Short: "Remove a vault password",
	RunE: func(cmd *cobra.Command, args []string) error {
		if 0 == len(flagPath) {
			return errors.New("--path is required")
		}

		if 8 > len(flagPassword) {
			return errors.New("--password must be at least 8 characters")
		}

		var err error
		v := vault.NewVault(flagPath)

		if err = v.Read(); nil != err {
			return err
		}

		if err = v.Authenticate(flagPassword); nil != err {
			return err
		}

		if err = v.RemovePassword(flagPassword); nil != err {
			return err
		}

		if err = v.Write(); nil != err {
			return err
		}

		fmt.Println("Password removed from vault successfully.")
		return nil
	},
}

func init() {
	passwordRemoveCmd.Flags().StringVar(&flagPath, "path", "", "Path to vault file")
	passwordRemoveCmd.Flags().StringVar(&flagPassword, "password", "", "Valid vault password (and the one to remove)")

	vault.Die(passwordRemoveCmd.MarkFlagRequired("path"))
	vault.Die(passwordRemoveCmd.MarkFlagRequired("password"))
}
