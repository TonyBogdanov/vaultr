package cli

import (
	"errors"
	"fmt"
	"vaultr/internal/vault"

	"github.com/spf13/cobra"
)

var entrySetCmd = &cobra.Command{
	Use:   "entry:set",
	Short: "Add/update a vault entry",
	RunE: func(cmd *cobra.Command, args []string) error {
		if 0 == len(flagPath) {
			return errors.New("--path is required")
		}

		if 8 > len(flagPassword) {
			return errors.New("--password must be at least 8 characters")
		}

		if 0 == len(flagKeys) {
			return errors.New("--key is required")
		}

		if 0 == len(flagValues) {
			return errors.New("--value is required")
		}

		if len(flagKeys) != len(flagValues) {
			return errors.New("--key and --value must be used equal number of times")
		}

		var err error
		v := vault.NewVault(flagPath)

		if err = v.Read(); nil != err {
			return err
		}

		if err = v.Authenticate(flagPassword); nil != err {
			return err
		}

		for i, key := range flagKeys {
			if err = v.SetValue(key, flagValues[i]); nil != err {
				return err
			}
		}

		if err = v.Write(); nil != err {
			return err
		}

		fmt.Println("Entry set in vault successfully.")
		return nil
	},
}

func init() {
	entrySetCmd.Flags().StringVar(&flagPath, "path", "", "Path to vault file")
	entrySetCmd.Flags().StringVar(&flagPassword, "password", "", "Valid vault password")
	entrySetCmd.Flags().StringArrayVar(&flagKeys, "key", nil, "The key of the entry (can be used multiple times)")
	entrySetCmd.Flags().StringArrayVar(&flagValues, "value", nil, "The value of the entry (can be used multiple times)")
}
