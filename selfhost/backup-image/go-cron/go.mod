// Pins go-cron for Dockerfile.backup: `go build github.com/prodrigestivill/go-cron` from this module links
// exactly the versions in go.sum. Regenerate with `go get -tool github.com/prodrigestivill/go-cron@<version>`
// then `go mod tidy`, inside the golang image Dockerfile.backup pins.
module chronicle-selfhost/go-cron

go 1.27.3

// go-cron's own go.mod says go 1.12, and `go install ...@v0.0.11` built it with go1.12's GODEBUG defaults
// (DefaultGODEBUG in `go version -m`, e.g. netedns0=0, panicnil=1, tlssha1=1). Keep them, so the binary
// behaves as before.
godebug default=go1.12

tool github.com/prodrigestivill/go-cron

require (
	github.com/prodrigestivill/go-cron v0.0.11 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
)
