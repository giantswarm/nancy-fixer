package nancy

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pterm/pterm"
	"github.com/stretchr/testify/require"
)

// fakeTools puts a go that lists nothing and a nancy running script first on
// PATH.
func fakeTools(t *testing.T, script string) {
	t.Helper()
	bin := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\nexit 0\n"), 0o755))   //nolint:gosec // a test executable
	require.NoError(t, os.WriteFile(filepath.Join(bin, "nancy"), []byte("#!/bin/sh\n"+script), 0o755)) //nolint:gosec // a test executable
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestRunSleuthReportsNancysOwnFailure(t *testing.T) {
	fakeTools(t, `cat >/dev/null
echo 'Error: guide API request failed: json: cannot unmarshal object into Go value of type []sonatypeguide.ComponentReportPost' >&2
exit 1
`)

	_, err := RunSleuth(pterm.DefaultLogger.WithWriter(io.Discard), t.TempDir())

	require.ErrorIs(t, err, ErrNancyFailed)
	require.NotErrorIs(t, err, ErrNancyParsingFailed)
	require.ErrorContains(t, err, "exit code 1")
	require.ErrorContains(t, err, "guide API request failed")
}

func TestRunSleuthReadsTheReportOfAFailingScan(t *testing.T) {
	fakeTools(t, `cat >/dev/null
echo '{"audited": [], "excluded": [], "exclusions": [], "vulnerable": []}'
exit 1
`)

	output, err := RunSleuth(pterm.DefaultLogger.WithWriter(io.Discard), t.TempDir())

	require.NoError(t, err)
	require.Empty(t, output.Audited)
}

func TestRunSleuthStillReportsAnUnreadableReport(t *testing.T) {
	fakeTools(t, `cat >/dev/null
echo 'not json'
exit 0
`)

	_, err := RunSleuth(pterm.DefaultLogger.WithWriter(io.Discard), t.TempDir())

	require.ErrorIs(t, err, ErrNancyParsingFailed)
}

func TestScanReportsTheMatchedExclusions(t *testing.T) {
	fakeTools(t, `cat >/dev/null
echo '{"num_audited": 3, "audited": [], "vulnerable": [], "exclusions": ["CVE-2026-107325", "sonatype-2026-1"],
  "excluded": [{"ID": "0a1b2c", "Cve": "CVE-2026-107325", "Excluded": true}, {"ID": "sonatype-2026-1", "Cve": "", "Excluded": true}]}'
exit 0
`)

	result, err := Scan(pterm.DefaultLogger.WithWriter(io.Discard), t.TempDir())

	require.NoError(t, err)
	require.Equal(t, 3, result.Audited)
	require.Equal(t, map[string]bool{"0a1b2c": true, "CVE-2026-107325": true, "sonatype-2026-1": true}, result.Matched)
	require.Empty(t, result.Vulnerable)
}

func TestRunSleuthListsPackagesWithoutCgo(t *testing.T) {
	fakeTools(t, `cat >/dev/null
echo '{"audited": [], "excluded": [], "exclusions": [], "vulnerable": []}'
`)
	bin := filepath.SplitList(os.Getenv("PATH"))[0]
	env := filepath.Join(t.TempDir(), "cgo")
	require.NoError(t, os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\necho \"$CGO_ENABLED\" > "+env+"\n"), 0o755)) //nolint:gosec // a test executable
	t.Setenv("CGO_ENABLED", "1")

	_, err := RunSleuth(pterm.DefaultLogger.WithWriter(io.Discard), t.TempDir())

	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Clean(env))
	require.NoError(t, err)
	require.Equal(t, "0\n", string(got))
}
