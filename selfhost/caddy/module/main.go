// Caddy with the rate-limit plugin: the main package `xcaddy build` generates (xcaddy v0.4, as run by the
// caddy:2.11.9-builder image), kept here so go.mod and go.sum fix every module version instead of `go get`
// choosing them at build time. Regenerate go.mod/go.sum as xcaddy did: `go mod init caddy`, the go-jose v3
// replace, `go get github.com/caddyserver/caddy/v2@<v> github.com/mholt/caddy-ratelimit@<v>`, `go mod tidy`.
package main

import (
	_ "time/tzdata"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// plug in Caddy modules here
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/mholt/caddy-ratelimit"
)

func main() {
	caddycmd.Main()
}
