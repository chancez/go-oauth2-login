/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/chancez/go-oauth2-login/pkg/login"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "login to an Oauth2 server",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Printf("%s needs to be able to create the directory %q with a 0755 permission", cmd.Name(), configDir)
			return err
		}
		l := &login.LoginConfig{
			Issuer:       vp.GetString("issuer"),
			ClientID:     vp.GetString("client-id"),
			ClientSecret: vp.GetString("client-secret"),
			Username:     vp.GetString("user"),
		}
		grantType := vp.GetString("grant-type")
		return login.LoginAndSave(cmd.Context(), logger, l, grantType, oidcLoginFile, oidcTokenFile)
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)

	fs := pflag.NewFlagSet("login", pflag.ContinueOnError)
	fs.String("issuer", "", "OIDC issuer url. Required for all grant-types.")
	fs.String("client-id", "", "OIDC application client ID. Required for all grant-types.")
	fs.String("client-secret", "", "OIDC application client secret. Required for all grant-types.")
	fs.String("user", "", "OIDC username. Used for password grant-type.")
	fs.String("grant-type", "auto", "One of: auto, authcode or password")
	loginCmd.Flags().AddFlagSet(fs)
	vp.BindPFlags(fs)
}
