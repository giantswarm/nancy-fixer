package modules

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/zip"
)

// TestUpdatePackageNeverAddsReplaceOrExclude bumps a vulnerable indirect
// dependency whose only parent has no newer version. The bump must raise the
// required version and must not write a replace or exclude directive, which
// `go install <module>@<version>` refuses.
func TestUpdatePackageNeverAddsReplaceOrExclude(t *testing.T) {
	proxy := t.TempDir()
	writeProxyModule(t, proxy, "example.com/vuln", "v1.0.0", "module example.com/vuln\n\ngo 1.21\n", map[string]string{
		"vuln.go": "package vuln\n\nfunc Version() string { return \"v1.0.0\" }\n",
	})
	writeProxyModule(t, proxy, "example.com/vuln", "v1.1.0", "module example.com/vuln\n\ngo 1.21\n", map[string]string{
		"vuln.go": "package vuln\n\nfunc Version() string { return \"v1.1.0\" }\n",
	})
	writeProxyModule(t, proxy, "example.com/parent", "v1.0.0", "module example.com/parent\n\ngo 1.21\n\nrequire example.com/vuln v1.0.0\n", map[string]string{
		"parent.go": "package parent\n\nimport \"example.com/vuln\"\n\nfunc Version() string { return vuln.Version() }\n",
	})

	t.Setenv("GOPROXY", "file://"+filepath.ToSlash(proxy))
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOFLAGS", "-modcacherw")
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOWORK", "off")

	cwd := t.TempDir()
	writeFile(t, filepath.Join(cwd, "go.mod"), "module example.com/app\n\ngo 1.21\n\nrequire example.com/parent v1.0.0\n\nrequire example.com/vuln v1.0.0 // indirect\n")
	writeFile(t, filepath.Join(cwd, "main.go"), "package main\n\nimport \"example.com/parent\"\n\nfunc main() { println(parent.Version()) }\n")
	// GetNewestVersion runs go in the working directory, as the fixer does
	t.Chdir(cwd)
	// a repository under remediation has a complete go.sum
	if err := runGo(cwd, "mod", "tidy"); err != nil {
		t.Fatalf("tidy the module under test: %v", err)
	}
	if got := readGoMod(t, cwd).Require; len(got) != 2 || got[1].Mod.Version != "v1.0.0" {
		t.Fatalf("expected the module under test to require example.com/vuln v1.0.0, got %v", got)
	}

	newest, err := GetNewestVersion("example.com/parent")
	if err != nil {
		t.Fatalf("get newest parent version: %v", err)
	}
	if newest != "v1.0.0" {
		t.Fatalf("expected the parent to have no update, newest is %s", newest)
	}

	newest, err = GetNewestVersion("example.com/vuln")
	if err != nil {
		t.Fatalf("get newest vuln version: %v", err)
	}

	err = UpdatePackage(cwd, "example.com/vuln", newest)
	if err != nil {
		t.Fatalf("update package: %v", err)
	}

	goMod := readGoMod(t, cwd)
	for _, r := range goMod.Replace {
		t.Errorf("go.mod carries replace %s => %s", r.Old, r.New)
	}
	for _, e := range goMod.Exclude {
		t.Errorf("go.mod carries exclude %s", e.Mod)
	}

	required := map[string]string{}
	for _, r := range goMod.Require {
		required[r.Mod.Path] = r.Mod.Version
	}
	if required["example.com/vuln"] != "v1.1.0" {
		t.Errorf("expected example.com/vuln v1.1.0 to be required, got %q", required["example.com/vuln"])
	}

	vetOk, vetErr := VetSuceeds(cwd)
	if !vetOk {
		t.Errorf("go vet failed after the bump: %v", vetErr)
	}
}

func writeProxyModule(t *testing.T, proxy, path, version, goMod string, files map[string]string) {
	t.Helper()

	src := t.TempDir()
	writeFile(t, filepath.Join(src, "go.mod"), goMod)
	for name, content := range files {
		writeFile(t, filepath.Join(src, name), content)
	}

	escaped, err := module.EscapePath(path)
	if err != nil {
		t.Fatalf("escape %s: %v", path, err)
	}
	dir := filepath.Join(proxy, filepath.FromSlash(escaped), "@v")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}

	writeFile(t, filepath.Join(dir, version+".mod"), goMod)
	writeFile(t, filepath.Join(dir, version+".info"), `{"Version":"`+version+`","Time":"2026-01-01T00:00:00Z"}`)

	z, err := os.Create(filepath.Join(dir, version+".zip"))
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer z.Close()
	err = zip.CreateFromDir(z, module.Version{Path: path, Version: version}, src)
	if err != nil {
		t.Fatalf("zip %s@%s: %v", path, version, err)
	}

	list, err := os.OpenFile(filepath.Join(dir, "list"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open version list: %v", err)
	}
	defer list.Close()
	if _, err := list.WriteString(version + "\n"); err != nil {
		t.Fatalf("write version list: %v", err)
	}
}

func readGoMod(t *testing.T, cwd string) *modfile.File {
	t.Helper()

	path := filepath.Join(cwd, "go.mod")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	goMod, err := modfile.Parse(path, data, nil)
	if err != nil {
		t.Fatalf("parse go.mod: %v", err)
	}
	return goMod
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
