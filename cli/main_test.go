package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func invoke(path string) (int, string, string) {
	request, _ := json.Marshal(map[string]string{"path": path})
	var out, err bytes.Buffer
	code := run(nil, bytes.NewReader(request), &out, &err)
	return code, out.String(), err.String()
}

func TestDigests(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("abc"), bytes.Repeat([]byte{0, 255, 13, 10, 128}, 20000)} {
		path := filepath.Join(t.TempDir(), "sample")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		code, out, stderr := invoke(path)
		if code != 0 || stderr != "" || out != hex.EncodeToString(sum[:])+"\n" {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out, stderr)
		}
	}
}

func TestSameSizeChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "changing")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	stat, _ := os.Stat(path)
	first, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("def"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, stat.ModTime(), stat.ModTime()); err != nil {
		t.Fatal(err)
	}
	second, err := hashFile(path)
	if err != nil || first == second {
		t.Fatalf("same-size update was not rehashed: %s %s %v", first, second, err)
	}
}

func TestPaths(t *testing.T) {
	names := []string{"日本語 café", "single'quote", "spaces ; $() & `literal`"}
	if runtime.GOOS != "windows" {
		names = append(names, `double"quote`, "line\nbreak")
	}
	for _, name := range names {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
			t.Fatal(err)
		}
		code, out, stderr := invoke(path)
		if code != 0 || len(out) != 65 || stderr != "" {
			t.Fatalf("path %q: %d %q %q", path, code, out, stderr)
		}
	}
}

func TestInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{dir, filepath.Join(dir, "missing")} {
		code, out, stderr := invoke(path)
		if code == 0 || out != "" || stderr == "" {
			t.Fatalf("path %q: %d %q %q", path, code, out, stderr)
		}
	}
}

func TestUnreadable(t *testing.T) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	path := filepath.Join(t.TempDir(), "unreadable")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		current, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		// icacls accepts SID syntax independently of localized account names.
		sid := "*" + current.Uid
		t.Cleanup(func() {
			if output, err := exec.Command("icacls", path, "/remove:d", sid).CombinedOutput(); err != nil {
				t.Errorf("restore ACL: %v %s", err, output)
			}
		})
		if output, err := exec.Command("icacls", path, "/deny", sid+":(R)").CombinedOutput(); err != nil {
			t.Fatalf("deny read ACL: %v %s", err, output)
		}
	} else {
		t.Cleanup(func() { _ = os.Chmod(path, 0600) })
		if err := os.Chmod(path, 0000); err != nil {
			t.Fatal(err)
		}
	}
	code, out, stderr := invoke(path)
	if code == 0 || out != "" || !strings.Contains(stderr, "open file") {
		t.Fatalf("unreadable: %d %q %q", code, out, stderr)
	}
	if runtime.GOOS == "windows" {
		t.Log("Windows unreadable-file check passed using icacls deny-read ACL; chmod is not used")
	}
}

func TestRequests(t *testing.T) {
	for _, request := range []string{
		"", "{", "null", "[]", `{"path":12}`, `{}`, `{"path":""}`,
		`{"path":"x","unknown":1}`, `{"path":"x"} {}`, `{"path":"x"} garbage`,
		strings.Repeat(" ", maxRequestBytes+1),
	} {
		var out, stderr bytes.Buffer
		if code := run(nil, strings.NewReader(request), &out, &stderr); code == 0 || out.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("accepted malformed request (length %d)", len(request))
		}
	}
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]string{"path": path})
	request := string(data) + strings.Repeat(" ", maxRequestBytes-len(data))
	var out, stderr bytes.Buffer
	if code := run(nil, strings.NewReader(request), &out, &stderr); code != 0 {
		t.Fatalf("exact 1 MiB rejected: %s", &stderr)
	}
}

func TestArguments(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"--architecture"}, {"--help"}, {"-h"}} {
		var out, stderr bytes.Buffer
		if run(args, nil, &out, &stderr) != 0 || out.Len() == 0 || stderr.Len() != 0 {
			t.Fatalf("arguments %v failed", args)
		}
		if args[0] == "--version" && out.String() != "20.0.1\n" {
			t.Fatal(out.String())
		}
		if args[0] == "--architecture" {
			want, err := hostArchitecture()
			if err != nil {
				t.Fatal(err)
			}
			if out.String() != want+"\n" {
				t.Fatalf("architecture output = %q; want %q", out.String(), want+"\n")
			}
		}
	}
	var out, stderr bytes.Buffer
	if run([]string{"file"}, nil, &out, &stderr) == 0 || out.Len() != 0 {
		t.Fatal("positional path accepted")
	}
	out.Reset()
	stderr.Reset()
	if run([]string{"--architecture", "file"}, nil, &out, &stderr) == 0 || out.Len() != 0 {
		t.Fatal("architecture mode accepted a positional path")
	}
}

type brokenFile struct {
	closed bool
}

func (*brokenFile) Read([]byte) (int, error) { return 0, errors.New("read failure") }
func (f *brokenFile) Close() error {
	f.closed = true
	return errors.New("close failure")
}

type closeFailure struct{ io.Reader }

func (closeFailure) Close() error { return errors.New("close failure") }

func TestIOFailures(t *testing.T) {
	file := &brokenFile{}
	digest, err := digestAndClose(file)
	if digest != "" || err == nil || !file.closed || !strings.Contains(err.Error(), "read file") || !strings.Contains(err.Error(), "close file") {
		t.Fatalf("lost read/close failure: %q %v", digest, err)
	}
	if digest, err := digestAndClose(closeFailure{strings.NewReader("abc")}); digest != "" || err == nil || !strings.Contains(err.Error(), "close file") {
		t.Fatalf("lost close failure: %q %v", digest, err)
	}
	var out, stderr bytes.Buffer
	if run(nil, file, &out, &stderr) == 0 || !strings.Contains(stderr.String(), "read JSON request") {
		t.Fatal("stdin read failure lost")
	}
}
