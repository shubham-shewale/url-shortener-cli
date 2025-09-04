module github.com/username/url-shortener-cli

go 1.23.0

toolchain go1.24.6

require (
	github.com/coreos/go-oidc/v3 v3.10.0
	github.com/google/uuid v1.6.0
	github.com/spf13/cobra v1.10.1
	github.com/stretchr/testify v1.8.4
	golang.org/x/oauth2 v0.13.0
	golang.org/x/term v0.34.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-jose/go-jose/v4 v4.0.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

replace github.com/username/url-shortener-types => ../url-shortener-types
