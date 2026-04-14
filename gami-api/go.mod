module authenticmemory.org/gami-api

go 1.22

require authenticmemory.org/gami-core v0.0.0

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/opentimestamps/go-opentimestamps v0.0.0 // indirect
	golang.org/x/crypto v0.18.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
)

// Local development: resolve gami-core from the sibling directory.
// Remove this replace directive when publishing gami-core to a registry.
replace authenticmemory.org/gami-core => ../gami-core

replace github.com/opentimestamps/go-opentimestamps => ../../go-opentimestamps
