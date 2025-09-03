package main

import (
	"bufio"
	"bytes"
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

	"github.com/spf13/cobra"
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

// Config represents the CLI configuration stored in ~/.shorten.yml
type Config struct {
	APIToken string `yaml:"api_token"`
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
	loginCmd = &cobra.Command{
		Use:   "login",
		Short: "Store API token for authentication",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogin()
		},
	}

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

// runLogin stores API token
func runLogin() error {
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

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
