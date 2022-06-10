/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/chancez/go-oauth2-login/pkg/login"
	"github.com/spf13/cobra"
)

var showLoginCmd = &cobra.Command{
	Use:     "logins",
	Aliases: []string{"login"},
	Short:   "Show your login configs",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		loginConfig, err := login.ReadLoginConfigs(oidcLoginFile)
		if err != nil {
			return err
		}

		var loginItem interface{} = loginConfig
		if len(args) == 1 {
			issuer := args[0]
			loginItem = loginConfig[issuer]
		}
		b, err := json.MarshalIndent(loginItem, "", "\t")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	},
}

func init() {
	showCmd.AddCommand(showLoginCmd)
}
