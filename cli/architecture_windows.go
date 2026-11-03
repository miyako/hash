package main

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

func hostArchitecture() (string, error) {
	procedure := syscall.NewLazyDLL("kernel32.dll").NewProc("IsWow64Process2")
	if err := procedure.Find(); err != nil {
		// Windows releases predating this API cannot emulate x64 on ARM64.
		if errors.Is(err, syscall.Errno(127)) {
			return runtime.GOARCH, nil
		}
		return "", fmt.Errorf("find IsWow64Process2: %w", err)
	}
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return "", fmt.Errorf("get current process: %w", err)
	}
	var processMachine, nativeMachine uint16
	ok, _, callErr := procedure.Call(uintptr(process),
		uintptr(unsafe.Pointer(&processMachine)), uintptr(unsafe.Pointer(&nativeMachine)))
	if ok == 0 {
		return "", fmt.Errorf("IsWow64Process2 failed: %w", callErr)
	}
	return machineArchitecture(nativeMachine)
}
