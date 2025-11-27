package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"vaultr/internal/vault"

	"github.com/spf13/cobra"
)

var dotEnvReplacer = strings.NewReplacer(
	`\\`, `\\\\`,
	`"`, `\"`,
	"\n", `\n`,
	"\r", `\r`,
	"\t", `\t`,
)

var entryListCmd = &cobra.Command{
	Use:   "entry:list",
	Short: "List stored vault entries",
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

		values, err := v.GetValues()
		if nil != err {
			return err
		}

		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}

		sort.Strings(keys)
		for _, key := range keys {
			fmt.Println(key + `="` + dotEnvReplacer.Replace(values[key]) + `"`)
		}

		return nil
	},
}

func init() {
	entryListCmd.Flags().StringVar(&flagPath, "path", "", "Path to vault file")
	entryListCmd.Flags().StringVar(&flagPassword, "password", "", "Valid vault password")
}
