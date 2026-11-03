// Package hash exposes the version embedded from the authoritative package manifest.
package hash

import (
	_ "embed"
	"encoding/json"
	"regexp"
)

//go:embed package.json
var manifest []byte

// Version returns the package version compiled into this binary.
func Version() string {
	var metadata struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifest, &metadata); err != nil {
		panic(err)
	}
	if !regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`).MatchString(metadata.Version) {
		panic("package.json requires a numeric major.minor.patch version")
	}
	return metadata.Version
}
