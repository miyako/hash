//go:build unix

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFIFO(t *testing.T) {
	if path := os.Getenv("HASH_FIFO_TEST_PATH"); path != "" {
		_, err := hashFile(path)
		if err == nil {
			t.Fatal("FIFO accepted")
		}
		return
	}
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFIFO$")
	cmd.Env = append(os.Environ(), "HASH_FIFO_TEST_PATH="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("FIFO check failed or hung: %v %s", err, output)
	}
}
