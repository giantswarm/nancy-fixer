package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giantswarm/nancy-fixer/internal/gomodtest"
)

// TestUpdatePackageNeverAddsReplaceOrExclude bumps a vulnerable indirect
// dependency whose only parent has no newer version. The bump must raise the
// required version and must not write a replace or exclude directive, which
// `go install <module>@<version>` refuses.
func TestUpdatePackageNeverAddsReplaceOrExclude(t *testing.T) {
	proxy := gomodtest.NewProxy(t)
	gomodtest.WriteModule(t, proxy, "example.com/vuln", "v1.0.0", "module example.com/vuln\n\ngo 1.21\n", map[string]string{
		"vuln.go": "package vuln\n\nfunc Version() string { return \"v1.0.0\" }\n",
	})
	gomodtest.WriteModule(t, proxy, "example.com/vuln", "v1.1.0", "module example.com/vuln\n\ngo 1.21\n", map[string]string{
		"vuln.go": "package vuln\n\nfunc Version() string { return \"v1.1.0\" }\n",
	})
	gomodtest.WriteModule(t, proxy, "example.com/parent", "v1.0.0", "module example.com/parent\n\ngo 1.21\n\nrequire example.com/vuln v1.0.0\n", map[string]string{
		"parent.go": "package parent\n\nimport \"example.com/vuln\"\n\nfunc Version() string { return vuln.Version() }\n",
	})

	cwd := t.TempDir()
	gomodtest.WriteFile(t, filepath.Join(cwd, "go.mod"), "module example.com/app\n\ngo 1.21\n\nrequire example.com/parent v1.0.0\n\nrequire example.com/vuln v1.0.0 // indirect\n")
	gomodtest.WriteFile(t, filepath.Join(cwd, "main.go"), "package main\n\nimport \"example.com/parent\"\n\nfunc main() { println(parent.Version()) }\n")
	// GetNewestVersion runs go in the working directory, as the fixer does
	t.Chdir(cwd)
	// a repository under remediation has a complete go.sum
	if err := runGo(cwd, "mod", "tidy"); err != nil {
		t.Fatalf("tidy the module under test: %v", err)
	}
	if got := gomodtest.ReadGoMod(t, cwd).Require; len(got) != 2 || got[1].Mod.Version != "v1.0.0" {
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

	goMod := gomodtest.ReadGoMod(t, cwd)
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

const (
	pseudoVersion = "v0.0.0-20260101000000-abcdefabcdef"
	vulnOld       = "v1.0.0"
	vulnNew       = "v1.1.0"
)

// TestGetNewestVersionWithoutTaggedVersion covers a fork pinned at a
// pseudo-version: the proxy lists no version for it, and the caller must be
// able to tell that from a failing lookup.
func TestGetNewestVersionWithoutTaggedVersion(t *testing.T) {
	proxy := gomodtest.NewProxy(t)
	gomodtest.WriteModule(t, proxy, "example.com/fork", pseudoVersion, "module example.com/fork\n\ngo 1.21\n", map[string]string{
		"fork.go": "package fork\n\nfunc Name() string { return \"fork\" }\n",
	})

	cwd := t.TempDir()
	gomodtest.WriteFile(t, filepath.Join(cwd, "go.mod"), "module example.com/app\n\ngo 1.21\n\nrequire example.com/fork "+pseudoVersion+"\n")
	gomodtest.WriteFile(t, filepath.Join(cwd, "main.go"), "package main\n\nimport \"example.com/fork\"\n\nfunc main() { println(fork.Name()) }\n")
	t.Chdir(cwd)
	if err := runGo(cwd, "mod", "tidy"); err != nil {
		t.Fatalf("tidy the module under test: %v", err)
	}

	_, err := GetNewestVersion("example.com/fork")
	if !IsNoVersionsFoundError(err) {
		t.Fatalf("expected no versions found, got %v", err)
	}
}

// TestGetVersionsForPackageMissingFromGoSum lists the versions of a module
// that is in the build graph but not in go.sum, which go refuses to look up
// under -mod=readonly. The parent predates module graph pruning (go 1.16), so
// go needs the go.mod checksum of its requirement.
func TestGetVersionsForPackageMissingFromGoSum(t *testing.T) {
	proxy := gomodtest.NewProxy(t)
	gomodtest.WriteModule(t, proxy, "example.com/vuln", vulnOld, "module example.com/vuln\n\ngo 1.21\n", nil)
	gomodtest.WriteModule(t, proxy, "example.com/vuln", vulnNew, "module example.com/vuln\n\ngo 1.21\n", nil)
	gomodtest.WriteModule(t, proxy, "example.com/parent", "v1.2.0", "module example.com/parent\n\ngo 1.16\n\nrequire example.com/vuln v1.0.0\n", map[string]string{
		"parent.go": "package parent\n\nfunc Name() string { return \"parent\" }\n",
	})

	cwd := t.TempDir()
	gomodtest.WriteFile(t, filepath.Join(cwd, "go.mod"), "module example.com/app\n\ngo 1.21\n\nrequire example.com/parent v1.2.0\n")
	gomodtest.WriteFile(t, filepath.Join(cwd, "main.go"), "package main\n\nimport \"example.com/parent\"\n\nfunc main() { println(parent.Name()) }\n")
	t.Chdir(cwd)
	if err := runGo(cwd, "mod", "tidy"); err != nil {
		t.Fatalf("tidy the module under test: %v", err)
	}
	removeGoSumLines(t, cwd, "example.com/vuln ")
	if err := runGo(cwd, "list", "-m", "-versions", "example.com/vuln"); err == nil {
		t.Fatal("expected go list -mod=readonly to refuse a module missing from go.sum")
	}

	versions, err := GetVersionsForPackage("example.com/vuln")
	if err != nil {
		t.Fatalf("list versions: %v", err)
	}
	if len(versions) != 2 || versions[0] != vulnOld || versions[1] != vulnNew {
		t.Fatalf("expected v1.0.0 and v1.1.0, got %v", versions)
	}
}

// TestGetNewestVersionUnknownModule keeps a failing lookup an error: only an
// empty version list means "no tagged version".
func TestGetNewestVersionUnknownModule(t *testing.T) {
	gomodtest.NewProxy(t)

	cwd := t.TempDir()
	gomodtest.WriteFile(t, filepath.Join(cwd, "go.mod"), "module example.com/app\n\ngo 1.21\n")
	t.Chdir(cwd)

	_, err := GetNewestVersion("example.com/missing")
	if err == nil || IsNoVersionsFoundError(err) {
		t.Fatalf("expected the lookup to fail, got %v", err)
	}
}

func removeGoSumLines(t *testing.T, cwd, prefix string) {
	t.Helper()

	path := filepath.Join(cwd, "go.sum")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read go.sum: %v", err)
	}
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, prefix) {
			kept = append(kept, line)
		}
	}
	gomodtest.WriteFile(t, path, strings.Join(kept, "\n"))
}
