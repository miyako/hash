package main

import "testing"

func TestArchitecture(t *testing.T) {
	tests := []struct {
		name    string
		machine uint16
		want    string
	}{
		{"Windows x64", 0x8664, "amd64"},
		{"Windows ARM64, including x64 emulation", 0xaa64, "arm64"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := machineArchitecture(test.machine)
			if err != nil || got != test.want {
				t.Fatalf("architecture = %q, %v; want %q", got, err, test.want)
			}
		})
	}
	if got, err := machineArchitecture(0); err == nil || got != "" {
		t.Fatal("unknown native architecture must fail without a default")
	}
}
