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

var showTokenCmd = &cobra.Command{
	Use:     "tokens",
	Aliases: []string{"token"},
	Short:   "Show your tokens",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		tokens, err := login.ReadTokens(oidcTokenFile)
		if err != nil {
			return err
		}

		var tokenItem interface{} = tokens
		if len(args) == 1 {
			issuer := args[0]
			tokenItem = tokens[issuer]
		}
		b, err := json.MarshalIndent(tokenItem, "", "\t")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	},
}

func init() {
	showCmd.AddCommand(showTokenCmd)
}
