# URL Shortener CLI

A command-line interface for managing shortened URLs via the URL Shortener API.

## Installation

```bash
# Clone the repository
git clone https://github.com/username/url-shortener-cli.git
cd url-shortener-cli

# Build the CLI
go build -o shorten .

# Or install globally
go install .
```

## Commands

- `shorten <url>` - Create a shortened URL
- `info <code>` - Get information about a shortened URL
- `delete <code>` - Delete a shortened URL
- `open <code>` - Open a shortened URL in browser
- `login` - Store API token for authentication
- `completion <shell>` - Generate shell completion script
- `version` - Print version information

## Examples

```bash
# Shorten a URL
shorten https://example.com

# Shorten with custom alias and password
shorten https://example.com --alias mylink --password secret123

# Shorten with expiry
shorten https://example.com --ttl 24h
shorten https://example.com --expire 2024-12-31T23:59:59Z

# Shorten with click limit
shorten https://example.com --max-clicks 100

# Get link information (text format)
shorten info abc123

# Get link information (JSON format)
shorten info abc123 --output json

# Delete a link (with confirmation)
shorten delete abc123

# Force delete without confirmation
shorten delete abc123 --force

# Open in browser
shorten open abc123

# Open password-protected link
shorten open abc123 --password secret123

# Login to store API token
shorten login

# Use custom API server
shorten --api https://my-api.com shorten https://example.com

# Set custom timeout
shorten --timeout 10s info abc123
```

## Global Flags

- `--api` - API server URL (default: http://localhost:8080)
- `--output` - Output format (text|json, default: text)
- `--timeout` - Request timeout (default: 5s)

## Shell Completion

Generate shell completion scripts for Bash, Zsh, Fish, or PowerShell:

```bash
# Bash
shorten completion bash > /etc/bash_completion.d/shorten

# Zsh
shorten completion zsh > "${fpath[1]}/_shorten"

# Fish
shorten completion fish > ~/.config/fish/completions/shorten.fish

# PowerShell
shorten completion powershell > shorten.ps1
```

## Testing

```bash
# Run unit tests
go test -v .

# Run with race detector
go test -race -v .
```

## Dependencies

This CLI depends on:
- [url-shortener-types](https://github.com/username/url-shortener-types) - Shared types
- [url-shortener](https://github.com/username/url-shortener) - API server