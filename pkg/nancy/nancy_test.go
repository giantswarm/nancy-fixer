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
