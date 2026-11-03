package main

import "strings"

func architecture(goos, goarch, processorArchW6432, processorArchitecture string) string {
	if goos == "windows" && goarch == "amd64" &&
		(strings.EqualFold(processorArchW6432, "ARM64") || strings.EqualFold(processorArchitecture, "ARM64")) {
		return "arm64"
	}
	return goarch
}
