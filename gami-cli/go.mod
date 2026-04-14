module authenticmemory.org/gami-cli

go 1.22

require (
	authenticmemory.org/gami-core v0.0.0
	github.com/spf13/cobra v1.8.1
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/opentimestamps/go-opentimestamps v0.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/crypto v0.18.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
)

// Local development: resolve gami-core from the sibling directory.
// Remove this replace directive when publishing gami-core to a registry.
replace authenticmemory.org/gami-core => ../gami-core

replace github.com/opentimestamps/go-opentimestamps => ../../go-opentimestamps
