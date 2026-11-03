//go:build unix

package main

import (
	"os"
	"syscall"
)

func openFile(path string) (*os.File, error) {
	// O_NONBLOCK prevents a FIFO substituted before open from hanging the helper.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
