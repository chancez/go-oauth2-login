package login

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/chancez/go-oauth2-login/oauth2params"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pkg/browser"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"golang.org/x/term"
)

func LoginAndSave(ctx context.Context, logger *zap.SugaredLogger, l *LoginConfig, grantType, oidcLoginFile, oidcTokenFile string) error {
	switch {
	case l.Issuer == "":
		return fmt.Errorf("must pass an issuer")
	case l.ClientID == "":
		return fmt.Errorf("must pass a client-id")
	case l.ClientSecret == "":
		return fmt.Errorf("must pass a client-secret")
	case grantType == "password" && l.Username == "":
		return fmt.Errorf("must pass a username")
	}

	provider, err := oidc.NewProvider(ctx, l.Issuer)
	if err != nil {
		return fmt.Errorf("error creating OIDC provider: %w", err)
	}
	oauth2Token, err := Login(ctx, logger, provider, l, oidcLoginFile, grantType)
	if err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}
	token, err := oauth2TokenToToken(ctx, provider, l, oauth2Token)
	if err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}
	err = saveCredentials(l, oidcLoginFile, token, oidcTokenFile)
	if err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}
	return nil
}

type LoginConfig struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	Username     string `json:"username"`
}

func Refresh(ctx context.Context, provider *oidc.Provider, l *LoginConfig, oidcTokenFile string) (*oauth2.Token, error) {
	oauth2Config := &oauth2.Config{
		ClientID:     l.ClientID,
		ClientSecret: l.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
	}

	savedToken, err := ReadToken(l.Issuer, oidcTokenFile)
	if err != nil {
		return nil, err
	}
	token, err := oauth2Config.TokenSource(ctx, &oauth2.Token{
		Expiry:       savedToken.Expiry,
		RefreshToken: savedToken.RefreshToken,
	}).Token()
	if err != nil {
		return nil, err
	}
	return token, nil
}

func Login(ctx context.Context, logger *zap.SugaredLogger, provider *oidc.Provider, l *LoginConfig, oidcTokenFile string, grantType string) (*oauth2.Token, error) {
	supportedGrants, err := GetSupportedGrants(provider)
	if err != nil {
		return nil, fmt.Errorf("unable to get supported grant types: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     l.ClientID,
		ClientSecret: l.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
	}

	// Before logging in, check if we already have creds that we can just refresh
	logger.Debug("checking if credentials already exist and can be refreshed")
	savedToken, err := ReadToken(l.Issuer, oidcTokenFile)

	// Refresh token flow, only used if we have valid creds with a refresh token.
	if err == nil && savedToken.RefreshToken != "" {
		if supportedGrants.Refresh {
			logger.Debug("found existing refresh token, attempting to refresh")
			token, err := oauth2Config.TokenSource(ctx, &oauth2.Token{
				RefreshToken: savedToken.RefreshToken,
			}).Token()
			if err != nil {
				logger.Warn("unable to refresh existing credentials for %q: %w", l.Issuer, err)
			} else {
				return token, nil
			}
		} else {
			logger.Warn("found existing refresh token, but IDP does not support refresh_token grant type")
		}
	}

	// Authorization code flow
	if (grantType == "auto" && supportedGrants.AuthorizationCode) || grantType == "authcode" {
		if !supportedGrants.AuthorizationCode && grantType == "authcode" {
			return nil, errors.New("specified --grant-type=authcode, but server does not support authorization_code grants")
		}
		pkce, err := oauth2params.NewPKCE()
		if err != nil {
			return nil, err
		}

		// ready will recieve the URL to open in the browser once the local web server is up
		ready := make(chan string, 1)
		defer close(ready)
		cfg := ServerConfig{
			OAuth2Config:           *oauth2Config,
			AuthCodeOptions:        pkce.AuthCodeOptions(),
			TokenRequestOptions:    pkce.TokenRequestOptions(),
			LocalServerReadyChan:   ready,
			LocalServerBindAddress: []string{"localhost:8000"},
			Logf:                   logger.With("component", "server").Debugf,
		}

		eg, ctx := errgroup.WithContext(ctx)

		// Start a go routine that's going to open the web-browser
		eg.Go(func() error {
			select {
			case url := <-ready:
				fmt.Printf("Open %s\n", url)
				if err := browser.OpenURL(url); err != nil {
					fmt.Printf("could not open the browser: %s\n", err)
				}
				return nil
			case <-ctx.Done():
				return fmt.Errorf("context done while waiting for authorization: %w", ctx.Err())
			}
		})

		// start a go routine that runs the local web server and initiates the login flow
		var token *oauth2.Token
		eg.Go(func() error {
			var err error
			token, err = AuthorizationCodeToken(ctx, cfg)
			if err != nil {
				return fmt.Errorf("could not get a token: %w", err)
			}
			fmt.Printf("You got a valid token until %s\n", token.Expiry)
			return nil
		})

		// Wait for the go routines to complete
		if err := eg.Wait(); err != nil {
			return nil, fmt.Errorf("authorization error: %s", err)
		}
		return token, nil
	}

	// Password flow
	if (grantType == "auto" && supportedGrants.Password) || grantType == "password" {
		if !supportedGrants.Password && grantType == "password" {
			return nil, errors.New("specified --grant-type=authcode, but server does not support password grants")
		}
		if grantType == "auto" && l.Username == "" {
			return nil, errors.New("specified --grant-type=auto, but --username was not specified, unable to do 'password' grant-type")
		}
		fmt.Println("Unable to reuse existing credentials, attempting login...")
		fmt.Fprintf(os.Stderr, "Enter your Password for %q: ", l.Issuer)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, fmt.Errorf("unable to read password: %w", err)
		}
		fmt.Fprint(os.Stderr, "\n")

		token, err := oauth2Config.PasswordCredentialsToken(ctx, l.Username, strings.TrimSpace(string(password)))
		if err != nil {
			return nil, fmt.Errorf("unable to exchange user credentials for oauth token: %w", err)
		}
		return token, nil
	}

	return nil, fmt.Errorf("unable to find a supported authentication grant type, grant-type: %q, supported grants: %s", grantType, supportedGrants)
}

type SupportedGrants struct {
	Refresh           bool
	AuthorizationCode bool
	Password          bool

	grantTypesSupported []string
}

func (g SupportedGrants) String() string {
	return "[" + strings.Join(g.grantTypesSupported, ", ") + "]"

}

func GetSupportedGrants(provider *oidc.Provider) (SupportedGrants, error) {
	var grants SupportedGrants
	var providerMetadata struct {
		GrantTypesSupported []string `json:"grant_types_supported"`
	}
	err := provider.Claims(&providerMetadata)
	if err != nil {
		return grants, fmt.Errorf("unable to unmarshal OIDC well-known metadata: %w", err)
	}

	// preserve the original list so we can log the full list of supported grant
	// types, even the ones we don't use/support.
	grants.grantTypesSupported = providerMetadata.GrantTypesSupported
	for _, grantType := range providerMetadata.GrantTypesSupported {
		switch grantType {
		case "refresh_token":
			grants.Refresh = true
		case "authorization_code":
			grants.AuthorizationCode = true
		case "password":
			grants.Password = true
		}
	}
	return grants, nil
}

func ReadLoginConfigs(oidcLoginFile string) (map[string]LoginConfig, error) {
	loginBytes, err := os.ReadFile(oidcLoginFile)
	if err != nil {
		return nil, err
	}
	var loginMap map[string]LoginConfig
	err = json.Unmarshal(loginBytes, &loginMap)
	if err != nil {
		return nil, fmt.Errorf("unable to parse existing login file %s: %w", oidcLoginFile, err)
	}
	return loginMap, nil
}

func oauth2TokenToToken(ctx context.Context, provider *oidc.Provider, l *LoginConfig, oauth2Token *oauth2.Token) (*Token, error) {
	oidcConfig := &oidc.Config{
		ClientID: l.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)

	var rawIDToken string
	var ok bool
	rawIDToken, ok = oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no ID token found in response")
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	return &Token{
		TokenType:     "Bearer",
		RawIDToken:    rawIDToken,
		IDTokenExpiry: idToken.Expiry,
		RefreshToken:  oauth2Token.RefreshToken,
		AccessToken:   oauth2Token.AccessToken,
		Expiry:        oauth2Token.Expiry,
		idToken:       idToken,
	}, nil
}

func saveCredentials(l *LoginConfig, oidcLoginFile string, token *Token, oidcTokenFile string) error {
	loginMap := map[string]LoginConfig{
		l.Issuer: *l,
	}
	// Save login file
	loginBytes, err := json.Marshal(&loginMap)
	if err != nil {
		return fmt.Errorf("could not marshal login data structure into json: %v", err)
	}
	err = os.WriteFile(oidcLoginFile, loginBytes, 0600)
	if err != nil {
		log.Printf("Was unable to write the login file, %q, to modify it: %v", oidcLoginFile, err)
	}

	// Store token in oidcTokenFile
	tokens := map[string]*Token{
		l.Issuer: token,
	}
	tokensJSON, err := json.Marshal(&tokens)
	if err != nil {
		return fmt.Errorf("failed to marshal the token into json to save to a file: %w", err)
	}
	err = os.WriteFile(oidcTokenFile, tokensJSON, 0600)
	if err != nil {
		return fmt.Errorf("was unable to write the token file, %q, to modify it: %v", oidcTokenFile, err)
	}
	return nil
}

func ReadTokens(oidcTokenFile string) (map[string]*Token, error) {
	tokenFile, err := os.Open(oidcTokenFile)
	if err != nil {
		return nil, err
	}
	st, err := tokenFile.Stat()
	if err != nil {
		return nil, err
	}
	// If the token file is gt 1MiB
	// then the file won't be read.
	if st.Size() > 1<<20 {
		return nil, fmt.Errorf("the token file is too big (greater than 1MiB) to open: %dB", st.Size())
	}

	tokensFileJSON, err := io.ReadAll(tokenFile)
	if err != nil {
		return nil, err
	}

	var tokens map[string]*Token
	err = json.Unmarshal(tokensFileJSON, &tokens)
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func ReadToken(issuer string, oidcTokenFile string) (*Token, error) {
	tokens, err := ReadTokens(oidcTokenFile)
	if err != nil {
		return nil, err
	}
	switch len(tokens) {
	case 0:
		return nil, fmt.Errorf("no tokens in file %s", oidcTokenFile)
	case 1:
		// if there's only one token in the file, use it, even if issuer wasn't set
		for _, value := range tokens {
			return value, nil
		}
	default:
		if issuer == "" {
			return nil, fmt.Errorf("no issuer set, but OIDC hubble config has multiple tokens from different issusers, please specify --issuer")
		}
	}

	token, ok := tokens[issuer]
	if !ok {
		return nil, fmt.Errorf("unable to find token for issuer %s", issuer)
	}
	return token, nil
}

// Token implements grpc.credentials.PerRPCCredentials interface.
type Token struct {
	TokenType     string    `json:"type"`
	AccessToken   string    `json:"access_token"`
	RefreshToken  string    `json:"refresh_token"`
	Expiry        time.Time `json:"expiry"`
	RawIDToken    string    `json:"id_token"`
	IDTokenExpiry time.Time `json:"id_token_expiry"`

	idToken *oidc.IDToken
}

func (t *Token) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": strings.Title(t.TokenType) + " " + string(t.RawIDToken),
	}, nil
}

func (t *Token) RequireTransportSecurity() bool {
	return true
}
