package main

import "fmt"

func machineArchitecture(machine uint16) (string, error) {
	switch machine {
	case 0xaa64:
		return "arm64", nil
	case 0x8664:
		return "amd64", nil
	default:
		return "", fmt.Errorf("unsupported native Windows machine: 0x%04x", machine)
	}
}
