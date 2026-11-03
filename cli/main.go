// Command hash computes a fresh SHA-256 digest of one regular file.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	hashversion "github.com/miyako/hash"
)

var version = hashversion.Version()

const maxRequestBytes = 1 << 20
const bufferBytes = 32 << 10

var usage = "hash " + version + `
Usage: hash [--version | --architecture | --help]
--architecture prints arm64 or amd64 (Windows x64 detects ARM64 hosts).
Without arguments, read one JSON object {"path":"..."} from stdin (maximum 1 MiB).
Print the regular file's SHA-256 as 64 lowercase hexadecimal characters and LF.
Errors are written to stderr with nonzero exit status.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var err error
	if len(args) != 0 {
		switch {
		case len(args) == 1 && args[0] == "--version":
			_, err = fmt.Fprintln(stdout, version)
		case len(args) == 1 && args[0] == "--architecture":
			var architecture string
			architecture, err = hostArchitecture()
			if err == nil {
				_, err = fmt.Fprintln(stdout, architecture)
			}
		case len(args) == 1 && (args[0] == "--help" || args[0] == "-h"):
			_, err = io.WriteString(stdout, usage)
		default:
			err = errors.New("unexpected arguments; use --help")
		}
	} else {
		var path, digest string
		path, err = requestPath(stdin)
		if err == nil {
			digest, err = hashFile(path)
		}
		if err == nil {
			_, err = fmt.Fprintln(stdout, digest)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "hash: %v\n", err)
		return 1
	}
	return 0
}

func requestPath(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxRequestBytes+1))
	if err != nil {
		return "", fmt.Errorf("read JSON request: %w", err)
	}
	if len(data) > maxRequestBytes {
		return "", errors.New("JSON request exceeds 1 MiB")
	}
	var request struct {
		Path string `json:"path"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return "", fmt.Errorf("invalid JSON request: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return "", errors.New("expected exactly one JSON request")
	}
	if request.Path == "" {
		return "", errors.New("JSON request requires a nonempty path string")
	}
	return request.Path, nil
}

func hashFile(path string) (string, error) {
	file, err := openFile(path)
	if err != nil {
		return "", fmt.Errorf("open file %q: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		return "", errors.Join(fmt.Errorf("stat file %q: %w", path, err), closeFile(file))
	}
	if !info.Mode().IsRegular() {
		return "", errors.Join(fmt.Errorf("file %q is not a regular file", path), closeFile(file))
	}
	return digestAndClose(file)
}

func closeFile(file io.Closer) error {
	if err := file.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}
	return nil
}

func digestAndClose(file io.ReadCloser) (string, error) {
	hash := sha256.New()
	// Hide optional WriterTo methods so CopyBuffer always uses this fixed buffer.
	_, readErr := io.CopyBuffer(hash, struct{ io.Reader }{file}, make([]byte, bufferBytes))
	if readErr != nil {
		readErr = fmt.Errorf("read file: %w", readErr)
	}
	if err := errors.Join(readErr, closeFile(file)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
