/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	configDir     string
	oidcLoginFile string
	oidcTokenFile string

	logger = zap.NewExample().Sugar()
	vp     = viper.New()

	rootCmd = &cobra.Command{
		Use:          "go-oauth2-login",
		Short:        "go-oauth2-login lets you login to an Oauth2 server",
		SilenceUsage: true,
	}
)

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	if dir, err := os.UserConfigDir(); err == nil {
		configDir = filepath.Join(dir, "go-oauth2-login")
	}
	oidcLoginFile = filepath.Join(configDir, "login.json")
	oidcTokenFile = filepath.Join(configDir, "oidc-token.jwt")
}
