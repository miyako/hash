//go:build !windows

package main

import "runtime"

func hostArchitecture() (string, error) {
	return runtime.GOARCH, nil
}
