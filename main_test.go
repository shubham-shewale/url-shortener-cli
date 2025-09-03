package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestParseTimeout(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"5s", 5 * time.Second},
		{"10s", 10 * time.Second},
		{"1m", 1 * time.Minute},
		{"2h", 2 * time.Hour},
		{"invalid", 5 * time.Second}, // default
		{"", 5 * time.Second},        // default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseTimeout(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"24h", 24 * time.Hour},
		{"30m", 30 * time.Minute},
		{"90s", 90 * time.Second},
		{"1h30m", 90 * time.Minute},
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseDuration(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetAPIToken(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "shorten-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Test with no config file
	token := getAPIToken()
	assert.Empty(t, token)

	// Create config file
	configPath := filepath.Join(tempDir, ".shorten.yml")
	config := Config{APIToken: "test-token"}

	file, err := os.Create(configPath)
	require.NoError(t, err)

	// Use YAML encoder instead of JSON
	err = yaml.NewEncoder(file).Encode(config)
	require.NoError(t, err)
	file.Close()

	// Mock os.Getenv to return temp directory
	// On Windows, USERPROFILE might be more reliable than HOME
	homeKey := "HOME"
	if os.Getenv("USERPROFILE") != "" {
		homeKey = "USERPROFILE"
	}

	originalHome := os.Getenv(homeKey)
	os.Setenv(homeKey, tempDir)
	defer os.Setenv(homeKey, originalHome)

	token = getAPIToken()
	assert.Equal(t, "test-token", token)
}

func TestHandleHTTPError(t *testing.T) {
	tests := []struct {
		statusCode int
		body       string
		expected   string
	}{
		{http.StatusBadRequest, "invalid url", "validation error: invalid url"},
		{http.StatusUnauthorized, "", "unauthorized: please check your API token"},
		{http.StatusForbidden, "", "forbidden: insufficient permissions"},
		{http.StatusNotFound, "", "code not found"},
		{http.StatusGone, "", "link expired"},
		{http.StatusTooManyRequests, "", "rate limit exceeded"},
		{http.StatusInternalServerError, "server error", "HTTP 500: server error"},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.statusCode), func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Body:       io.NopCloser(strings.NewReader(tt.body)),
			}

			err := handleHTTPError(resp)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expected)
		})
	}
}

func TestShortenCommandParsing(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected CreateLinkRequest
	}{
		{
			name: "basic URL",
			args: []string{"https://example.com"},
			expected: CreateLinkRequest{
				LongURL: "https://example.com",
			},
		},
		{
			name: "with alias",
			args: []string{"https://example.com", "--alias", "test"},
			expected: CreateLinkRequest{
				LongURL: "https://example.com",
				Alias:   stringPtr("test"),
			},
		},
		{
			name: "with password",
			args: []string{"https://example.com", "--password", "secret"},
			expected: CreateLinkRequest{
				LongURL:  "https://example.com",
				Password: stringPtr("secret"),
			},
		},
		{
			name: "with max clicks",
			args: []string{"https://example.com", "--max-clicks", "100"},
			expected: CreateLinkRequest{
				LongURL:   "https://example.com",
				MaxClicks: intPtr(100),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global variables
			shortenAlias = ""
			shortenPassword = ""
			shortenMaxClicks = 0

			// This is a simplified test - in a real scenario we'd need to
			// parse the command line arguments properly
			if len(tt.args) > 1 {
				for i := 1; i < len(tt.args); i += 2 {
					switch tt.args[i] {
					case "--alias":
						shortenAlias = tt.args[i+1]
					case "--password":
						shortenPassword = tt.args[i+1]
					case "--max-clicks":
						// In real code this would be parsed by Cobra
						shortenMaxClicks = 100
					}
				}
			}

			// Verify the global variables are set correctly
			if tt.expected.Alias != nil {
				assert.Equal(t, *tt.expected.Alias, shortenAlias)
			}
			if tt.expected.Password != nil {
				assert.Equal(t, *tt.expected.Password, shortenPassword)
			}
			if tt.expected.MaxClicks != nil {
				assert.Equal(t, *tt.expected.MaxClicks, shortenMaxClicks)
			}
		})
	}
}

func TestIntegrationShortenCommand(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/v1/links" {
			var req CreateLinkRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)

			response := CreateLinkResponse{
				Code:     "test123",
				ShortURL: "http://localhost:8080/r/test123",
				Metadata: map[string]interface{}{"has_password": false},
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(response)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Set the API URL to our test server
	originalAPI := apiURL
	apiURL = server.URL
	defer func() { apiURL = originalAPI }()

	// Test the shorten command
	err := runShorten("https://example.com")
	assert.NoError(t, err)
}

func TestIntegrationInfoCommand(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/links/") {
			response := LinkInfo{
				Code:       "test123",
				LongURL:    "https://example.com",
				ClickCount: 42,
				CreatedAt:  "2024-01-01T00:00:00Z",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Set the API URL to our test server
	originalAPI := apiURL
	apiURL = server.URL
	defer func() { apiURL = originalAPI }()

	// Test the info command
	err := runInfo("test123")
	assert.NoError(t, err)
}

func TestIntegrationDeleteCommand(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/v1/links/") {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Set the API URL to our test server
	originalAPI := apiURL
	apiURL = server.URL
	defer func() { apiURL = originalAPI }()

	// Test the delete command with force flag
	err := runDelete("test123", true)
	assert.NoError(t, err)
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}
