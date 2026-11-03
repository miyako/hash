//go:build !unix

package main

import (
	"fmt"
	"os"
)

func openFile(path string) (*os.File, error) {
	// Reject named pipes and devices before opening on platforms without O_NONBLOCK.
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("file %q is not a regular file", path)
	}
	return os.Open(path)
}
