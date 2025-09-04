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
- `login` - Authenticate with API server (API token or OAuth)
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

# Login with API token (legacy)
shorten login

# Login with OAuth 2.0
shorten login --provider auth0 --issuer https://your-domain.auth0.com --client-id your-client-id

# Use custom API server
shorten --api https://my-api.com shorten https://example.com

# Set custom timeout
shorten --timeout 10s info abc123
```

## Authentication

The CLI supports two authentication methods:

### API Token (Legacy)

Store an API token for authentication:

```bash
shorten login
```

This will prompt you to enter your API token, which will be stored in `~/.shorten.yml`.

### OAuth 2.0

Authenticate using OAuth 2.0 with PKCE flow:

```bash
shorten login --provider auth0 --issuer https://your-domain.auth0.com --client-id your-client-id
```

Supported providers:
- Auth0
- Google Identity Platform
- Keycloak
- Any OIDC-compliant provider

The OAuth flow will:
1. Launch your browser to the identity provider
2. Handle the authorization callback on `http://localhost:53682`
3. Store access tokens in `~/.shorten.yml`

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