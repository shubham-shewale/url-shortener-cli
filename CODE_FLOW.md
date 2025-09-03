# URL Shortener CLI - Code Flow Documentation

This document explains how the URL Shortener CLI works, designed for programmers coming from other languages (JavaScript, Python, Java, etc.).

## 🏗️ **Architecture Overview**

```
┌─────────────────┐    HTTP     ┌─────────────────┐
│   CLI Client    │ ──────────► │   API Server    │
│                 │             │                 │
│ • Command Line  │             │ • REST API      │
│ • Input Parsing │             │ • Business Logic│
│ • HTTP Requests │             │ • Database      │
│ • Response      │ ◄────────── │ • Caching       │
│   Formatting    │             │                 │
└─────────────────┘             └─────────────────┘
```

## 📋 **CLI Command Flow**

### 1. **Entry Point (`main.go`)**

```go
func main() {
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}
```

**What this does:**
- `rootCmd` is a Cobra command object (like a CLI framework)
- `Execute()` parses command line arguments and runs the appropriate command
- Similar to `sys.argv` parsing in Python or `process.argv` in Node.js

### 2. **Command Registration**

```go
var rootCmd = &cobra.Command{
    Use:   "shorten",
    Short: "URL shortener CLI",
    Long:  `A CLI tool for managing shortened URLs`,
}

func init() {
    rootCmd.PersistentFlags().StringVar(&apiURL, "api", "http://localhost:8080", "API server URL")
    rootCmd.PersistentFlags().StringVar(&output, "output", "text", "Output format")
    rootCmd.PersistentFlags().StringVar(&timeout, "timeout", "5s", "Request timeout")
}
```

**Key Concepts:**
- **Global Variables**: `apiURL`, `output`, `timeout` are package-level variables
- **Persistent Flags**: Available to all subcommands (like global options)
- **Init Function**: Runs automatically before `main()` (Go's constructor pattern)

### 3. **Shorten Command Example**

```go
var shortenCmd = &cobra.Command{
    Use:   "shorten <url>",
    Short: "Create a shortened URL",
    Args:  cobra.ExactArgs(1),  // Requires exactly 1 argument
    RunE: func(cmd *cobra.Command, args []string) error {
        // Command logic here
        return nil
    },
}
```

**Flow:**
1. **Argument Validation**: `cobra.ExactArgs(1)` ensures one URL provided
2. **Flag Parsing**: Access flags via global variables (`shortenAlias`, `shortenPassword`, etc.)
3. **HTTP Request**: Make POST request to API
4. **Response Handling**: Parse JSON response and format output

## 🌐 **HTTP Request Flow**

### Making an HTTP Request

```go
// 1. Create request data
req := CreateLinkRequest{
    LongURL: url,
    Alias:   &shortenAlias,  // Pointer to string (nil if not set)
}

// 2. Marshal to JSON
jsonData, err := json.Marshal(req)

// 3. Create HTTP request
httpReq, err := http.NewRequest("POST", apiURL+"/v1/links", bytes.NewBuffer(jsonData))
httpReq.Header.Set("Content-Type", "application/json")

// 4. Add auth token if available
if token := getAPIToken(); token != "" {
    httpReq.Header.Set("Authorization", "Bearer "+token)
}

// 5. Execute request
client := &http.Client{Timeout: parseTimeout(timeout)}
resp, err := client.Do(httpReq)
```

**Key Go Concepts:**
- **Structs**: `CreateLinkRequest` is like a class/object
- **JSON Marshalling**: Converting Go structs to JSON (like `JSON.stringify()`)
- **Error Handling**: Every operation returns an error that must be checked
- **Pointers**: `&shortenAlias` allows nil values for optional fields

### Response Handling

```go
// 1. Check HTTP status
if resp.StatusCode != http.StatusCreated {
    return handleHTTPError(resp)
}

// 2. Parse JSON response
var response CreateLinkResponse
if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
    return fmt.Errorf("failed to decode response: %v", err)
}

// 3. Format output based on flags
if output == "json" {
    return json.NewEncoder(os.Stdout).Encode(response)
} else {
    fmt.Printf("Short URL: %s\n", response.ShortURL)
}
```

## 🔐 **Authentication Flow**

### Token Storage

```go
func getAPIToken() string {
    configPath := filepath.Join(os.UserHomeDir(), ".shorten.yml")
    file, err := os.Open(configPath)
    if err != nil {
        return ""  // No token found
    }
    defer file.Close()

    var config Config
    if err := yaml.NewDecoder(file).Decode(&config); err != nil {
        return ""
    }
    return config.APIToken
}
```

**File Operations:**
- `os.Open()`: Opens file for reading
- `defer file.Close()`: Ensures file closes when function exits
- `yaml.NewDecoder()`: Parses YAML format

### Login Command

```go
func saveAPIToken(token string) error {
    configPath := filepath.Join(os.UserHomeDir(), ".shorten.yml")
    config := Config{APIToken: token}

    file, err := os.Create(configPath)
    if err != nil {
        return err
    }
    defer file.Close()

    return yaml.NewEncoder(file).Encode(config)
}
```

## 🛠️ **Key Go Patterns & Concepts**

### 1. **Error Handling**
```go
// Every operation that can fail returns an error
result, err := someFunction()
if err != nil {
    return fmt.Errorf("failed to do something: %v", err)
}
```

**Comparison:**
- **Go**: Explicit error checking
- **JavaScript**: `try/catch` blocks
- **Python**: Exceptions
- **Java**: Checked exceptions

### 2. **Structs & JSON**
```go
type CreateLinkRequest struct {
    LongURL   string     `json:"long_url"`
    Alias     *string    `json:"alias,omitempty"`  // Pointer allows nil
    Password  *string    `json:"password,omitempty"`
    ExpiresAt *time.Time `json:"expires_at,omitempty"`
}
```

**Key Points:**
- **Tags**: `json:"long_url"` controls JSON field names
- **Pointers**: `*string` allows `nil` for optional fields
- **omitempty**: Skip field in JSON if zero value

### 3. **Interfaces & Dependency Injection**
```go
type LinkStorage interface {
    Create(ctx context.Context, link *Link) error
    GetByCode(ctx context.Context, code string) (*Link, error)
    // ... other methods
}
```

**Benefits:**
- **Testability**: Easy to mock interfaces
- **Flexibility**: Can swap implementations (PostgreSQL, Redis, etc.)
- **Clean Architecture**: Business logic doesn't depend on specific storage

### 4. **Context for Cancellation**
```go
func (s *LinkService) CreateLink(ctx context.Context, req *CreateLinkRequest) (*CreateLinkResponse, error) {
    // Context allows request cancellation
    link, err := s.storage.GetByCode(ctx, code)
    // ...
}
```

**Use Cases:**
- HTTP request cancellation
- Timeout handling
- Graceful shutdown

## 🔄 **Complete Request Flow**

### User runs: `shorten https://example.com --alias mylink`

1. **CLI Parsing**
   - Cobra parses command and flags
   - `args[0]` = `"https://example.com"`
   - `shortenAlias` = `"mylink"`

2. **Request Building**
   ```go
   req := CreateLinkRequest{
       LongURL: "https://example.com",
       Alias:   &shortenAlias,  // Points to "mylink"
   }
   ```

3. **HTTP Request**
   ```go
   POST /v1/links
   Content-Type: application/json
   {
     "long_url": "https://example.com",
     "alias": "mylink"
   }
   ```

4. **API Processing**
   - Validate URL format
   - Check if alias is available
   - Generate short code
   - Store in database
   - Return response

5. **Response Handling**
   ```json
   {
     "code": "mylink",
     "short_url": "http://localhost:8080/r/mylink",
     "metadata": {
       "has_password": false
     }
   }
   ```

6. **Output Formatting**
   ```
   Short URL: http://localhost:8080/r/mylink
   Code: mylink
   ```

## 🧪 **Testing Patterns**

### Unit Tests
```go
func TestParseTimeout(t *testing.T) {
    tests := []struct {
        input    string
        expected time.Duration
    }{
        {"5s", 5 * time.Second},
        {"10s", 10 * time.Second},
        {"invalid", 5 * time.Second}, // default
    }

    for _, tt := range tests {
        result := parseTimeout(tt.input)
        assert.Equal(t, tt.expected, result)
    }
}
```

**Table-Driven Tests**: Common Go pattern for testing multiple cases

### Integration Tests
```go
func TestShortenCommandIntegration(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Mock API responses
    }))
    defer server.Close()

    // Test CLI against mock server
}
```

## 🚀 **Deployment & Build**

### Local Development
```bash
# Build CLI
go build -o shorten .

# Run tests
go test -v .

# Install globally
go install .
```

### Production Build
```bash
# With version info
go build -ldflags "-X main.version=v1.0.0 -X main.commit=abc123" -o shorten .
```

## 📚 **Learning Resources**

- **Go Tour**: https://tour.golang.org/
- **Effective Go**: https://golang.org/doc/effective_go.html
- **Go by Example**: https://gobyexample.com/
- **Cobra CLI**: https://github.com/spf13/cobra

## 🔄 **Comparison with Other Languages**

| Concept | Go | JavaScript | Python | Java |
|---------|-----|------------|--------|------|
| CLI Framework | Cobra | Commander | argparse | Apache Commons CLI |
| HTTP Client | net/http | fetch/axios | requests | HttpClient |
| JSON Handling | encoding/json | JSON.parse() | json.loads() | Jackson/Gson |
| Error Handling | Multiple returns | try/catch | try/except | try/catch |
| Structs | struct | object | dict/class | class |
| Pointers | *T | N/A | N/A | references |
| Interfaces | interface | duck typing | protocols | interfaces |
| Goroutines | go keyword | async/await | threading | threads |

This architecture provides a clean, testable, and maintainable CLI that follows Go best practices while being accessible to developers from other languages.