// Package gomodtest serves modules to the go command from a directory, so
// tests run go get, go list and go mod tidy without the network.
package gomodtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/zip"
)

// NewProxy returns an empty proxy directory and points the go command of the test
// at it, with its own module cache and no checksum database.
func NewProxy(t *testing.T) string {
	t.Helper()

	proxy := t.TempDir()
	// GOPROXY is a list split at commas and pipes
	if strings.ContainsAny(proxy, ",|") {
		t.Fatalf("proxy path %s has a comma or a pipe: rename the test", proxy)
	}
	t.Setenv("GOPROXY", "file://"+filepath.ToSlash(proxy))
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOFLAGS", "-modcacherw")
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOWORK", "off")
	return proxy
}

// WriteModule adds path@version to the proxy. Like a real proxy, the version
// list names tagged versions only: a module served at pseudo-versions only
// has none.
func WriteModule(t *testing.T, proxy, path, version, goMod string, files map[string]string) {
	t.Helper()

	src := t.TempDir()
	WriteFile(t, filepath.Join(src, "go.mod"), goMod)
	for name, content := range files {
		WriteFile(t, filepath.Join(src, name), content)
	}

	escaped, err := module.EscapePath(path)
	if err != nil {
		t.Fatalf("escape %s: %v", path, err)
	}
	dir := filepath.Join(proxy, filepath.FromSlash(escaped), "@v")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}

	WriteFile(t, filepath.Join(dir, version+".mod"), goMod)
	WriteFile(t, filepath.Join(dir, version+".info"), `{"Version":"`+version+`","Time":"2026-01-01T00:00:00Z"}`)

	z, err := os.Create(filepath.Clean(filepath.Join(dir, version+".zip")))
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	err = zip.CreateFromDir(z, module.Version{Path: path, Version: version}, src)
	if err != nil {
		t.Fatalf("zip %s@%s: %v", path, version, err)
	}
	if err := z.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}

	listPath := filepath.Join(dir, "list")
	list, err := os.ReadFile(filepath.Clean(listPath))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read version list: %v", err)
	}
	if !module.IsPseudoVersion(version) {
		list = append(list, version+"\n"...)
	}
	WriteFile(t, listPath, string(list))
}

func WriteFile(t *testing.T, path, content string) {
	t.Helper()

	// the paths are test temp directories
	// #nosec G703
	if err := os.WriteFile(filepath.Clean(path), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func ReadGoMod(t *testing.T, cwd string) *modfile.File {
	t.Helper()

	path := filepath.Join(cwd, "go.mod")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	goMod, err := modfile.Parse(path, data, nil)
	if err != nil {
		t.Fatalf("parse go.mod: %v", err)
	}
	return goMod
}
