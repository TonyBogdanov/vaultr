package cli

import (
  "errors"
  "fmt"
  "vaultr/internal/vault"

  "github.com/spf13/cobra"
)

var passwordAddCmd = &cobra.Command{
  Use:   "password:add",
  Short: "Add a new vault password",
  RunE: func(cmd *cobra.Command, args []string) error {
    if 0 == len(flagPath) {
      return errors.New("--path is required")
    }

    if 8 > len(flagPassword) {
      return errors.New("--password must be at least 8 characters")
    }

    if 8 > len(flagNewPassword) {
      return errors.New("--new-password must be at least 8 characters")
    }

    var err error
    v := vault.NewVault(flagPath)

    if err = v.Read(); nil != err {
      return err
    }

    if err = v.Authenticate(flagPassword); nil != err {
      return err
    }

    if err = v.AddPassword(flagNewPassword); nil != err {
      return err
    }

    if err = v.Write(); nil != err {
      return err
    }

    fmt.Println("Password added to vault successfully.")
    return nil
  },
}

func init() {
  passwordAddCmd.Flags().StringVar(&flagPath, "path", "", "Path to vault file")
  passwordAddCmd.Flags().StringVar(&flagPassword, "password", "", "Valid vault password")
  passwordAddCmd.Flags().StringVar(&flagNewPassword, "new-password", "", "Password to add to the vault (min 8 chars)")

  vault.Die(passwordAddCmd.MarkFlagRequired("path"))
  vault.Die(passwordAddCmd.MarkFlagRequired("password"))
  vault.Die(passwordAddCmd.MarkFlagRequired("new-password"))
}
