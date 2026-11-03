package main

import "testing"

func TestArchitecture(t *testing.T) {
	tests := []struct {
		name, goos, goarch, w6432, processor, want string
	}{
		{"Windows x64 native", "windows", "amd64", "", "AMD64", "amd64"},
		{"Windows x64 missing environment", "windows", "amd64", "", "", "amd64"},
		{"Windows x64 ARM64 W6432", "windows", "amd64", "ARM64", "AMD64", "arm64"},
		{"Windows x64 ARM64 processor", "windows", "amd64", "AMD64", "ARM64", "arm64"},
		{"Windows x64 ARM64 both", "windows", "amd64", "arm64", "ArM64", "arm64"},
		{"Windows x64 case insensitive W6432", "windows", "amd64", "aRm64", "", "arm64"},
		{"Windows x64 no substring match", "windows", "amd64", "NOTARM64", "ARM64other", "amd64"},
		{"Windows ARM64 ignores x64 environment", "windows", "arm64", "AMD64", "AMD64", "arm64"},
		{"macOS x64 ignores ARM64 environment", "darwin", "amd64", "ARM64", "ARM64", "amd64"},
		{"macOS ARM64 ignores x64 environment", "darwin", "arm64", "AMD64", "AMD64", "arm64"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := architecture(test.goos, test.goarch, test.w6432, test.processor)
			if got != test.want {
				t.Fatalf("architecture = %q; want %q", got, test.want)
			}
		})
	}
}
