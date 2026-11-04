package fix

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pterm/pterm"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/nancy-fixer/internal/gomodtest"
	"github.com/giantswarm/nancy-fixer/pkg/gocli"
	"github.com/giantswarm/nancy-fixer/pkg/modules"
	"github.com/giantswarm/nancy-fixer/pkg/modules/revisions"
	"github.com/giantswarm/nancy-fixer/pkg/nancy"
)

const (
	pseudoVersion = "v0.0.0-20260101000000-abcdefabcdef"
	vulnOld       = "v1.0.0"
	vulnNew       = "v1.1.0"
	vulnModule    = "example.com/vuln"
	cve           = "CVE-2024-12886"
)

// TestFixVulnerablePackage runs the fix against modules served from a local
// proxy; only the nancy scan is faked. The parent example.com/fork stands for
// a fork pinned at a pseudo-version, which has no tagged version to update to.
// It is either required directly or, as in a real fork, through a replace of
// the upstream module example.com/upstream.
func TestFixVulnerablePackage(t *testing.T) {
	testCases := []struct {
		name string
		// vulnVersion is the version of example.com/vuln the app requires.
		vulnVersion string
		// newerVuln is a newer tagged version of example.com/vuln, if any.
		newerVuln string
		// replaced requires the fork through a replace of example.com/upstream.
		replaced bool
		// vulnerable are the versions of example.com/vuln the fake scan reports.
		vulnerable     []string
		expectedResult FixResult
		expectedVuln   string
		expectedIgnore bool
	}{
		{
			name:        "parent without tagged version: the bump fixes the finding",
			vulnVersion: vulnOld,
			newerVuln:   vulnNew,
			vulnerable:  []string{vulnOld},
			expectedResult: FixResult{
				ParentResult: ParentUpdateNoUpdateAvailable,
				BumpResult:   BumpSuccess,
			},
			expectedVuln: vulnNew,
		},
		{
			name:        "parent without tagged version: the bump does not fix the finding",
			vulnVersion: vulnOld,
			newerVuln:   vulnNew,
			vulnerable:  []string{vulnOld, vulnNew},
			expectedResult: FixResult{
				ParentResult: ParentUpdateNoUpdateAvailable,
				BumpResult:   BumpDidNotFixVulnerability,
				Ignored:      true,
			},
			expectedVuln:   vulnOld,
			expectedIgnore: true,
		},
		{
			name:        "parent replaced by a fork: the bump fixes the finding",
			vulnVersion: vulnOld,
			newerVuln:   vulnNew,
			replaced:    true,
			vulnerable:  []string{vulnOld},
			expectedResult: FixResult{
				ParentResult: ParentUpdateNoUpdateAvailable,
				BumpResult:   BumpSuccess,
			},
			expectedVuln: vulnNew,
		},
		{
			name:        "parent replaced by a fork: the bump does not fix the finding",
			vulnVersion: vulnOld,
			newerVuln:   vulnNew,
			replaced:    true,
			vulnerable:  []string{vulnOld, vulnNew},
			expectedResult: FixResult{
				ParentResult: ParentUpdateNoUpdateAvailable,
				BumpResult:   BumpDidNotFixVulnerability,
				Ignored:      true,
			},
			expectedVuln:   vulnOld,
			expectedIgnore: true,
		},
		{
			name:        "vulnerable module without tagged version is ignored",
			vulnVersion: pseudoVersion,
			vulnerable:  []string{pseudoVersion},
			expectedResult: FixResult{
				ParentResult: ParentNotTried,
				BumpResult:   BumpNotTried,
				Ignored:      true,
			},
			expectedVuln:   pseudoVersion,
			expectedIgnore: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			proxy := gomodtest.NewProxy(t)
			for _, v := range []string{tc.vulnVersion, tc.newerVuln} {
				if v == "" {
					continue
				}
				gomodtest.WriteModule(t, proxy, vulnModule, v, "module example.com/vuln\n\ngo 1.21\n", map[string]string{
					"vuln.go": "package vuln\n\nfunc Name() string { return \"vuln\" }\n",
				})
			}
			cwd := t.TempDir()
			writeApp(t, proxy, cwd, tc.vulnVersion, tc.replaced)

			fakeScan(t, tc.vulnerable)
			history, err := revisions.BuildHistory(cwd)
			require.NoError(t, err)

			p := nancy.VulnerablePackage{
				Name:            vulnModule,
				Version:         modules.SemanticVersion(tc.vulnVersion),
				Vulnerabilities: []nancy.Vulnerability{{ID: cve}},
			}
			logger := pterm.DefaultLogger.WithWriter(io.Discard)

			result, _, err := FixVulnerablePackage(logger, cwd, p, history, nancy.IgnorePolicy{})
			require.NoError(t, err)
			require.Equal(t, tc.expectedResult, result)
			require.Equal(t, tc.expectedVuln, requiredVersion(t, cwd, vulnModule))

			ignore, err := os.ReadFile(filepath.Clean(filepath.Join(cwd, DefaultNancyIgnorePath)))
			if tc.expectedIgnore {
				require.NoError(t, err)
				require.True(t, strings.HasPrefix(string(ignore), cve+" "), "ignore file: %q", ignore)
			} else {
				require.True(t, os.IsNotExist(err), "expected no ignore file, got %q", ignore)
			}
		})
	}
}

// writeApp writes the module under test, which imports the fork, and the fork,
// which requires example.com/vuln at vulnVersion.
func writeApp(t *testing.T, proxy, cwd, vulnVersion string, replaced bool) {
	t.Helper()

	// a replacement declares the path of the module it replaces
	forkPath := "example.com/fork"
	goMod := "module example.com/app\n\ngo 1.21\n\nrequire example.com/fork " + pseudoVersion + "\n"
	if replaced {
		forkPath = "example.com/upstream"
		// like github.com/kagent-dev/kagent/go, the upstream is on the proxy
		// without a tagged version
		gomodtest.WriteModule(t, proxy, forkPath, pseudoVersion, "module "+forkPath+"\n\ngo 1.21\n", nil)
		goMod = "module example.com/app\n\ngo 1.21\n\nrequire example.com/upstream v0.0.0\n\nreplace example.com/upstream => example.com/fork " + pseudoVersion + "\n"
	}

	gomodtest.WriteModule(t, proxy, "example.com/fork", pseudoVersion, "module "+forkPath+"\n\ngo 1.21\n\nrequire example.com/vuln "+vulnVersion+"\n", map[string]string{
		"fork.go": "package fork\n\nimport \"example.com/vuln\"\n\nfunc Name() string { return vuln.Name() }\n",
	})
	gomodtest.WriteFile(t, filepath.Join(cwd, "go.mod"), goMod)
	gomodtest.WriteFile(t, filepath.Join(cwd, "main.go"), "package main\n\nimport fork \""+forkPath+"\"\n\nfunc main() { println(fork.Name()) }\n")
	// a repository under remediation has a complete go.sum
	var stdout, stderr bytes.Buffer
	require.NoError(t, gocli.CallGo(gocli.GoConfig{Cwd: cwd}, &stdout, &stderr, "mod", "tidy"))
}

// fakeScan reports example.com/vuln as vulnerable while the module under test
// requires one of the given versions.
func fakeScan(t *testing.T, vulnerable []string) {
	t.Helper()

	original := getVulnerablePackages
	t.Cleanup(func() { getVulnerablePackages = original })

	getVulnerablePackages = func(_ *pterm.Logger, dir string) ([]nancy.VulnerablePackage, error) {
		version := requiredVersion(t, dir, vulnModule)
		for _, v := range vulnerable {
			if v == version {
				return []nancy.VulnerablePackage{{
					Name:            vulnModule,
					Version:         modules.SemanticVersion(version),
					Vulnerabilities: []nancy.Vulnerability{{ID: cve}},
				}}, nil
			}
		}
		return nil, nil
	}
}

func requiredVersion(t *testing.T, cwd, path string) string {
	t.Helper()

	for _, r := range gomodtest.ReadGoMod(t, cwd).Require {
		if r.Mod.Path == path {
			return r.Mod.Version
		}
	}
	t.Fatalf("go.mod does not require %s", path)
	return ""
}
