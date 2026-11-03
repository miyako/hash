package hash

import (
	"encoding/json"
	"os"
	"testing"
)

func TestVersionMatchesPackageManifest(t *testing.T) {
	data, err := os.ReadFile("package.json")
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatal(err)
	}
	if Version() != metadata.Version {
		t.Fatalf("embedded version %q differs from package.json %q", Version(), metadata.Version)
	}
}
