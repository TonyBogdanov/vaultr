package cli

import (
	"errors"
	"fmt"
	"vaultr/internal/vault"

	"github.com/spf13/cobra"
)

var entryRemoveCmd = &cobra.Command{
	Use:   "entry:remove",
	Short: "Remove a vault entry",
	RunE: func(cmd *cobra.Command, args []string) error {
		if 0 == len(flagPath) {
			return errors.New("--path is required")
		}

		if 8 > len(flagPassword) {
			return errors.New("password must be at least 8 characters")
		}

		if 0 == len(flagKeys) {
			return errors.New("--key is required")
		}

		var err error
		v := vault.NewVault(flagPath)

		if err = v.Read(); nil != err {
			return err
		}

		if err = v.Authenticate(flagPassword); nil != err {
			return err
		}

		for _, key := range flagKeys {
			if err = v.RemoveValue(key); nil != err {
				return err
			}
		}

		if err = v.Write(); nil != err {
			return err
		}

		fmt.Println("Entry removed from vault successfully.")
		return nil
	},
}

func init() {
	entryRemoveCmd.Flags().StringVar(&flagPath, "path", "", "Path to vault file")
	entryRemoveCmd.Flags().StringVar(&flagPassword, "password", "", "Valid vault password")
	entryRemoveCmd.Flags().StringArrayVar(&flagKeys, "key", nil, "The key of the entry (can be used multiple times)")
}
