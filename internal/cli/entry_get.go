package cli

import (
	"errors"
	"fmt"
	"vaultr/internal/vault"

	"github.com/spf13/cobra"
)

var entryGetCmd = &cobra.Command{
	Use:   "entry:get",
	Short: "Retrieve the value of a vault entry",
	RunE: func(cmd *cobra.Command, args []string) error {
		if 0 == len(flagPath) {
			return errors.New("--path is required")
		}

		if 8 > len(flagPassword) {
			return errors.New("--password must be at least 8 characters")
		}

		if 0 == len(flagKey) {
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

		value, err := v.GetValue(flagKey)
		if nil != err {
			return err
		}

		fmt.Print(value)
		return nil
	},
}

func init() {
	entryGetCmd.Flags().StringVar(&flagPath, "path", "", "Path to vault file")
	entryGetCmd.Flags().StringVar(&flagPassword, "password", "", "Valid vault password")
	entryGetCmd.Flags().StringVar(&flagKey, "key", "", "The key of the entry")
}
