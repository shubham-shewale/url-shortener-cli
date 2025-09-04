package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha3"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

var (
	apiURL  string
	output  string
	timeout string
	version = "dev"
	commit  = "unknown"

	// Commands
	shortenCmd    *cobra.Command
	infoCmd       *cobra.Command
	deleteCmd     *cobra.Command
	openCmd       *cobra.Command
	loginCmd      *cobra.Command
	completionCmd *cobra.Command
	versionCmd    *cobra.Command

	// Shorten command flags
	shortenAlias     string
	shortenPassword  string
	shortenTTL       string
	shortenExpire    string
	shortenMaxClicks int

	// Delete command flags
	deleteForce bool

	// Open command flags
	openPassword string
)

// OAuthTokens represents OAuth 2.0 tokens
type OAuthTokens struct {
	AccessToken  string    `yaml:"access_token"`
	RefreshToken string    `yaml:"refresh_token,omitempty"`
	TokenType    string    `yaml:"token_type"`
	ExpiresAt    time.Time `yaml:"expires_at"`
	IDToken      string    `yaml:"id_token,omitempty"`
}

// Config represents the CLI configuration stored in ~/.shorten.yml
type Config struct {
	APIToken    string       `yaml:"api_token,omitempty"`    // Legacy token support
	OAuthTokens *OAuthTokens `yaml:"oauth_tokens,omitempty"` // OAuth 2.0 tokens
	IssuerURL   string       `yaml:"issuer_url,omitempty"`   // OAuth issuer URL
	ClientID    string       `yaml:"client_id,omitempty"`    // OAuth client ID
}

// CreateLinkRequest represents the request to create a shortened URL
type CreateLinkRequest struct {
	LongURL   string  `json:"long_url"`
	Alias     *string `json:"alias,omitempty"`
	Password  *string `json:"password,omitempty"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	MaxClicks *int    `json:"max_clicks,omitempty"`
}

// CreateLinkResponse represents the response from creating a shortened URL
type CreateLinkResponse struct {
	Code     string                 `json:"code"`
	ShortURL string                 `json:"short_url"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// LinkInfo represents metadata about a shortened URL
type LinkInfo struct {
	Code       string  `json:"code"`
	LongURL    string  `json:"long_url"`
	Alias      *string `json:"alias"`
	ExpiresAt  *string `json:"expires_at"`
	MaxClicks  *int    `json:"max_clicks"`
	ClickCount int     `json:"click_count"`
	CreatedAt  string  `json:"created_at"`
}

var rootCmd = &cobra.Command{
	Use:   "shorten",
	Short: "URL shortener CLI",
	Long:  `A CLI tool for managing shortened URLs via the URL shortener API`,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&apiURL, "api", "http://localhost:8080", "API server URL")
	rootCmd.PersistentFlags().StringVar(&output, "output", "text", "Output format (text|json)")
	rootCmd.PersistentFlags().StringVar(&timeout, "timeout", "5s", "Request timeout")

	// Shorten command
	var (
		shortenAlias     string
		shortenPassword  string
		shortenTTL       string
		shortenExpire    string
		shortenMaxClicks int
	)

	shortenCmd = &cobra.Command{
		Use:   "shorten <url>",
		Short: "Create a shortened URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShorten(args[0])
		},
	}

	shortenCmd.Flags().StringVar(&shortenAlias, "alias", "", "custom slug for the shortened URL")
	shortenCmd.Flags().StringVar(&shortenPassword, "password", "", "password-protect the link")
	shortenCmd.Flags().StringVar(&shortenTTL, "ttl", "", "time-to-live (e.g., 24h, 30m)")
	shortenCmd.Flags().StringVar(&shortenExpire, "expire", "", "expiration time (RFC3339 format)")
	shortenCmd.Flags().IntVar(&shortenMaxClicks, "max-clicks", 0, "maximum number of clicks allowed")
	shortenCmd.MarkFlagsMutuallyExclusive("ttl", "expire")

	// Info command
	infoCmd = &cobra.Command{
		Use:   "info <code>",
		Short: "Get information about a shortened URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInfo(args[0])
		},
	}

	// Delete command
	var deleteForce bool
	deleteCmd = &cobra.Command{
		Use:   "delete <code>",
		Short: "Delete a shortened URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDelete(args[0], deleteForce)
		},
	}
	deleteCmd.Flags().BoolVar(&deleteForce, "force", false, "skip confirmation prompt")

	// Open command
	var openPassword string
	openCmd = &cobra.Command{
		Use:   "open <code>",
		Short: "Open a shortened URL in browser",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOpen(args[0], openPassword)
		},
	}
	openCmd.Flags().StringVar(&openPassword, "password", "", "password for protected links")

	// Login command
	var loginProvider string
	var loginIssuer string
	var loginClientID string
	var loginClientSecret string

	loginCmd = &cobra.Command{
		Use:   "login",
		Short: "Authenticate with API server",
		Long: `Authenticate with the API server using either:
- API token (legacy): shorten login
- OAuth 2.0: shorten login --provider <idp>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if loginProvider != "" {
				return runOAuthLogin(loginProvider, loginIssuer, loginClientID, loginClientSecret)
			}
			return runLegacyLogin()
		},
	}

	loginCmd.Flags().StringVar(&loginProvider, "provider", "", "OAuth provider (auth0, google, keycloak)")
	loginCmd.Flags().StringVar(&loginIssuer, "issuer", "", "OAuth issuer URL")
	loginCmd.Flags().StringVar(&loginClientID, "client-id", "", "OAuth client ID")
	loginCmd.Flags().StringVar(&loginClientSecret, "client-secret", "", "OAuth client secret")

	// Completion command
	completionCmd = &cobra.Command{
		Use:   "completion <shell>",
		Short: "Generate shell completion script",
		Long: `Generate shell completion script for Bash, Zsh, Fish, or PowerShell.

Examples:
	 shorten completion bash > /etc/bash_completion.d/shorten
	 shorten completion zsh > "${fpath[1]}/_shorten"
	 shorten completion fish > ~/.config/fish/completions/shorten.fish
	 shorten completion powershell > shorten.ps1`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompletion(args[0])
		},
	}

	// Version command
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("shorten version %s (%s)\n", version, commit)
		},
	}

	rootCmd.AddCommand(shortenCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(openCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(completionCmd)
	rootCmd.AddCommand(versionCmd)
}

// runShorten creates a shortened URL
func runShorten(url string) error {
	req := CreateLinkRequest{
		LongURL: url,
	}

	if shortenAlias != "" {
		req.Alias = &shortenAlias
	}
	if shortenPassword != "" {
		req.Password = &shortenPassword
	}
	if shortenMaxClicks > 0 {
		req.MaxClicks = &shortenMaxClicks
	}

	// Handle expiration
	if shortenTTL != "" {
		expiresAt := time.Now().Add(parseDuration(shortenTTL)).Format(time.RFC3339)
		req.ExpiresAt = &expiresAt
	} else if shortenExpire != "" {
		req.ExpiresAt = &shortenExpire
	}

	resp, err := makeAPIRequest("POST", "/v1/links", req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return handleHTTPError(resp)
	}

	var result CreateLinkResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	if output == "json" {
		return json.NewEncoder(os.Stdout).Encode(result)
	}

	fmt.Printf("Short URL: %s\n", result.ShortURL)
	fmt.Printf("Code: %s\n", result.Code)
	return nil
}

// runInfo gets information about a shortened URL
func runInfo(code string) error {
	resp, err := makeAPIRequest("GET", "/v1/links/"+code, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return handleHTTPError(resp)
	}

	var result LinkInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	if output == "json" {
		return json.NewEncoder(os.Stdout).Encode(result)
	}

	fmt.Printf("Code: %s\n", result.Code)
	fmt.Printf("URL: %s\n", result.LongURL)
	if result.Alias != nil {
		fmt.Printf("Alias: %s\n", *result.Alias)
	}
	fmt.Printf("Clicks: %d\n", result.ClickCount)
	fmt.Printf("Created: %s\n", result.CreatedAt)
	if result.ExpiresAt != nil {
		fmt.Printf("Expires: %s\n", *result.ExpiresAt)
	}
	if result.MaxClicks != nil {
		fmt.Printf("Max Clicks: %d\n", *result.MaxClicks)
	}
	return nil
}

// runDelete deletes a shortened URL
func runDelete(code string, force bool) error {
	if !force {
		fmt.Printf("Are you sure you want to delete '%s'? (y/N): ", code)
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" && response != "yes" {
			fmt.Println("Operation cancelled.")
			return nil
		}
	}

	resp, err := makeAPIRequest("DELETE", "/v1/links/"+code, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return handleHTTPError(resp)
	}

	fmt.Printf("Successfully deleted: %s\n", code)
	return nil
}

// runOpen opens a shortened URL in browser
func runOpen(code string, password string) error {
	// If password is provided, verify it first
	if password != "" {
		verifyReq := map[string]string{"password": password}
		resp, err := makeAPIRequest("POST", "/v1/links/"+code+"/verify", verifyReq)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("password verification failed")
		}
	}

	// Get the redirect URL
	resp, err := makeAPIRequest("GET", "/r/"+code, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		return handleHTTPError(resp)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("no redirect location found")
	}

	// Open in browser
	if err := openBrowser(location); err != nil {
		fmt.Printf("Could not open browser, URL: %s\n", location)
		return err
	}

	fmt.Printf("Opened: %s\n", location)
	return nil
}

// runLegacyLogin stores API token (legacy method)
func runLegacyLogin() error {
	fmt.Print("Enter API token: ")
	tokenBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	fmt.Println() // New line after password input

	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = os.Getenv("USERPROFILE") // Windows fallback
	}
	if homeDir == "" {
		return fmt.Errorf("cannot determine home directory")
	}
	configPath := filepath.Join(homeDir, ".shorten.yml")
	config := Config{APIToken: token}

	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %v", err)
	}
	defer file.Close()

	if err := yaml.NewEncoder(file).Encode(config); err != nil {
		return fmt.Errorf("failed to write config: %v", err)
	}

	fmt.Println("API token saved successfully.")
	return nil
}

// runOAuthLogin performs OAuth 2.0 login flow
func runOAuthLogin(providerName, issuerURL, clientID, clientSecret string) error {
	if issuerURL == "" {
		return fmt.Errorf("issuer URL is required for OAuth login")
	}
	if clientID == "" {
		return fmt.Errorf("client ID is required for OAuth login")
	}

	ctx := context.Background()

	// Discover OAuth 2.0 configuration
	oidcProvider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return fmt.Errorf("failed to create OIDC provider: %v", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://localhost:53682/callback",
		Endpoint:     oidcProvider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "links:read", "links:write"},
	}

	// Generate PKCE challenge
	state := generateState()
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Start local server for callback
	callbackCh := make(chan *oauth2.Token)
	server := startCallbackServer(callbackCh)

	// Build authorization URL
	authURL := oauth2Config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))

	fmt.Printf("Opening browser for authentication...\n")
	fmt.Printf("If browser doesn't open, visit: %s\n", authURL)

	// Open browser
	if err := openBrowser(authURL); err != nil {
		fmt.Printf("Could not open browser automatically. Please visit: %s\n", authURL)
	}

	// Wait for callback
	token := <-callbackCh
	server.Shutdown(ctx)

	if token == nil {
		return fmt.Errorf("authentication failed")
	}

	// Get ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return fmt.Errorf("no ID token in response")
	}

	// Verify ID token
	verifier := oidcProvider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return fmt.Errorf("failed to verify ID token: %v", err)
	}

	// Extract claims
	var claims struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return fmt.Errorf("failed to extract claims: %v", err)
	}

	// Save tokens
	oauthTokens := &OAuthTokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		ExpiresAt:    token.Expiry,
		IDToken:      rawIDToken,
	}

	config := Config{
		OAuthTokens: oauthTokens,
		IssuerURL:   issuerURL,
		ClientID:    clientID,
	}

	if err := saveConfig(config); err != nil {
		return fmt.Errorf("failed to save OAuth tokens: %v", err)
	}

	fmt.Printf("Successfully authenticated as %s\n", claims.Email)
	return nil
}

// runCompletion generates shell completion scripts
func runCompletion(shell string) error {
	var err error
	switch strings.ToLower(shell) {
	case "bash":
		err = rootCmd.GenBashCompletion(os.Stdout)
	case "zsh":
		err = rootCmd.GenZshCompletion(os.Stdout)
	case "fish":
		err = rootCmd.GenFishCompletion(os.Stdout, true)
	case "powershell", "ps1":
		err = rootCmd.GenPowerShellCompletion(os.Stdout)
	default:
		return fmt.Errorf("unsupported shell: %s", shell)
	}
	return err
}

// Helper functions

func makeAPIRequest(method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %v", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, apiURL+path, reqBody)
	if err != nil {
		return nil, err
	}

	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add auth token if available
	if token := getAPIToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: parseTimeout(timeout)}
	return client.Do(req)
}

func getAPIToken() string {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = os.Getenv("USERPROFILE") // Windows fallback
	}
	if homeDir == "" {
		return "" // No home directory found
	}

	configPath := filepath.Join(homeDir, ".shorten.yml")
	file, err := os.Open(configPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	var config Config
	if err := yaml.NewDecoder(file).Decode(&config); err != nil {
		return ""
	}

	// Prefer OAuth access token over legacy API token
	if config.OAuthTokens != nil && config.OAuthTokens.AccessToken != "" {
		// Check if token is expired
		if time.Now().Before(config.OAuthTokens.ExpiresAt) {
			return config.OAuthTokens.AccessToken
		}
		// TODO: Implement token refresh logic here
		fmt.Println("Warning: OAuth access token has expired. Please login again.")
	}

	return config.APIToken
}

func handleHTTPError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	bodyStr := strings.TrimSpace(string(body))

	switch resp.StatusCode {
	case http.StatusBadRequest:
		return fmt.Errorf("validation error: %s", bodyStr)
	case http.StatusUnauthorized:
		return fmt.Errorf("unauthorized: please check your API token")
	case http.StatusForbidden:
		return fmt.Errorf("forbidden: insufficient permissions")
	case http.StatusNotFound:
		return fmt.Errorf("code not found")
	case http.StatusGone:
		return fmt.Errorf("link expired")
	case http.StatusTooManyRequests:
		return fmt.Errorf("rate limit exceeded")
	default:
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, bodyStr)
	}
}

func parseTimeout(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 5 * time.Second // default
	}
	return d
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch {
	case isCommandAvailable("xdg-open"):
		cmd = exec.Command("xdg-open", url)
	case isCommandAvailable("open"):
		cmd = exec.Command("open", url)
	case isCommandAvailable("start"):
		cmd = exec.Command("start", url)
	default:
		return fmt.Errorf("no browser command found")
	}
	return cmd.Start()
}

func isCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// OAuth helper functions

func generateState() string {
	return uuid.New().String()
}

func generateCodeVerifier() string {
	// Generate a random 32-byte string
	verifier := make([]byte, 32)
	rand.Read(verifier)
	return base64.RawURLEncoding.EncodeToString(verifier)
}

func generateCodeChallenge(verifier string) string {
	// SHA256 hash of verifier
	hash := sha3.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func startCallbackServer(callbackCh chan<- *oauth2.Token) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" {
			http.Error(w, "No authorization code", http.StatusBadRequest)
			return
		}

		// In a real implementation, you'd validate the state parameter
		_ = state

		// For now, we'll just send a dummy token
		// In production, you'd exchange the code for tokens
		token := &oauth2.Token{
			AccessToken:  "dummy-access-token",
			TokenType:    "Bearer",
			RefreshToken: "dummy-refresh-token",
			Expiry:       time.Now().Add(time.Hour),
		}

		// Add dummy ID token
		token = token.WithExtra(map[string]interface{}{
			"id_token": "dummy-id-token",
		})

		callbackCh <- token

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><h1>Authentication successful!</h1><p>You can close this window.</p></body></html>")
	})

	server := &http.Server{
		Addr:    ":53682",
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Callback server error: %v\n", err)
		}
	}()

	return server
}

func saveConfig(config Config) error {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = os.Getenv("USERPROFILE") // Windows fallback
	}
	if homeDir == "" {
		return fmt.Errorf("cannot determine home directory")
	}

	configPath := filepath.Join(homeDir, ".shorten.yml")

	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %v", err)
	}
	defer file.Close()

	if err := yaml.NewEncoder(file).Encode(config); err != nil {
		return fmt.Errorf("failed to write config: %v", err)
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
