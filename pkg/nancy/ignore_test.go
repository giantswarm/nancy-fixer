package nancy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/nancy-fixer/pkg/modules"
)

func testPackage(t *testing.T) VulnerablePackage {
	t.Helper()

	version, err := modules.BuildSemVer("v1.2.3")
	require.NoError(t, err)

	return VulnerablePackage{
		Name:    modules.PackageName("github.com/foo/bar"),
		Version: version,
	}
}

func day(offsetDays int) string {
	return time.Now().AddDate(0, 0, offsetDays).Format(dateLayout)
}

// fresh is a newly written entry for the package under test.
func fresh(cve string, since string) string {
	return fmt.Sprintf("%s until=%s # github.com/foo/bar@v1.2.3 since=%s", cve, day(DefaultIgnorePeriodDays), since)
}

func TestGenerateNancyIgnoreEntry(t *testing.T) {
	p := testPackage(t)

	testCases := []struct {
		name     string
		since    string
		expected string
	}{
		{
			name:     "first ignore records today as the first ignore date",
			since:    "",
			expected: fresh("CVE-2022-29153", day(0)),
		},
		{
			name:     "renewal keeps the first ignore date",
			since:    "2026-03-04",
			expected: fresh("CVE-2022-29153", "2026-03-04"),
		},
		{
			name:     "unparsable first ignore date falls back to today",
			since:    "not-a-date",
			expected: fresh("CVE-2022-29153", day(0)),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, generateNancyIgnoreEntry(Vulnerability{ID: "CVE-2022-29153"}, p, tc.since))
		})
	}
}

func TestParseIgnoreEntry(t *testing.T) {
	testCases := []struct {
		name     string
		line     string
		expected ignoreEntry
		ok       bool
	}{
		{
			name:     "entry with a first ignore date",
			line:     "CVE-2022-29153 until=2026-10-17 # github.com/foo/bar@v1.2.3 since=2026-03-04",
			expected: ignoreEntry{cve: "CVE-2022-29153", until: "2026-10-17", since: "2026-03-04"},
			ok:       true,
		},
		{
			name:     "entry without a first ignore date",
			line:     "CVE-2022-29153 until=2026-10-17 # github.com/foo/bar@v1.2.3",
			expected: ignoreEntry{cve: "CVE-2022-29153", until: "2026-10-17"},
			ok:       true,
		},
		{
			name:     "entry with extra spacing",
			line:     "CVE-2022-29153  until=2026-10-17  #  github.com/foo/bar@v1.2.3  since=2026-03-04",
			expected: ignoreEntry{cve: "CVE-2022-29153", until: "2026-10-17", since: "2026-03-04"},
			ok:       true,
		},
		{
			name: "line without an expiration date",
			line: "CVE-2022-29153 # not applicable, we do not use this code path",
		},
		{
			name: "line with the expiration date in the wrong position",
			line: "CVE-2022-29153 # github.com/foo/bar@v1.2.3 until=2026-10-17",
		},
		{
			name: "line holding only an expiration date",
			line: "until=2026-10-17",
		},
		{
			name: "empty line",
			line: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			entry, ok := parseIgnoreEntry(tc.line)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.expected, entry)
		})
	}
}

func TestUpdateNancyIgnoreLines(t *testing.T) {
	p := testPackage(t)

	unexpiredOther := fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0 since=%s", day(3), day(-10))

	testCases := []struct {
		name            string
		lines           []string
		vulnerabilities []Vulnerability
		expected        []string
	}{
		{
			name:            "first ignore of a vulnerability",
			lines:           []string{},
			vulnerabilities: []Vulnerability{{ID: "CVE-2022-29153"}},
			expected:        []string{fresh("CVE-2022-29153", day(0))},
		},
		{
			name:            "renewal keeps the first ignore date of the existing entry",
			lines:           []string{fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0 since=2026-03-04", day(3))},
			vulnerabilities: []Vulnerability{{ID: "CVE-2022-29153"}},
			expected:        []string{fresh("CVE-2022-29153", "2026-03-04")},
		},
		{
			name:            "renewal of a legacy entry treats the vulnerability as first seen now",
			lines:           []string{fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0", day(3))},
			vulnerabilities: []Vulnerability{{ID: "CVE-2022-29153"}},
			expected:        []string{fresh("CVE-2022-29153", day(0))},
		},
		{
			name:            "expired entry for a vulnerability that is gone is dropped",
			lines:           []string{fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0 since=%s", day(-1), day(-40))},
			vulnerabilities: []Vulnerability{},
			expected:        []string{},
		},
		{
			name:            "unexpired entry for a vulnerability that is gone is kept unchanged",
			lines:           []string{unexpiredOther},
			vulnerabilities: []Vulnerability{},
			expected:        []string{unexpiredOther},
		},
		{
			name:            "line without an expiration date is deleted",
			lines:           []string{"CVE-2022-29153 # not applicable, we do not use this code path"},
			vulnerabilities: []Vulnerability{},
			expected:        []string{},
		},
		{
			name:            "comment and blank lines are kept",
			lines:           []string{"# grpc: no newer release", "", unexpiredOther},
			vulnerabilities: []Vulnerability{},
			expected:        []string{"# grpc: no newer release", "", unexpiredOther},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lines, overdue := updateNancyIgnoreLines(tc.lines, tc.vulnerabilities, p, IgnorePolicy{})
			require.Equal(t, tc.expected, lines)
			require.Empty(t, overdue)
		})
	}
}

func TestUpdateNancyIgnoreLinesReportsOverdue(t *testing.T) {
	p := testPackage(t)

	entrySince := func(sinceOffsetDays int) string {
		return fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0 since=%s", day(3), day(sinceOffsetDays))
	}

	testCases := []struct {
		name     string
		lines    []string
		policy   IgnorePolicy
		expected []OverdueIgnore
	}{
		{
			name:     "policy disabled reports nothing",
			lines:    []string{entrySince(-200)},
			policy:   IgnorePolicy{MaxAgeDays: DefaultMaxIgnoreAgeDays},
			expected: []OverdueIgnore{},
		},
		{
			name:   "renewal older than the threshold is overdue",
			lines:  []string{entrySince(-200)},
			policy: IgnorePolicy{ReportOverdue: true, MaxAgeDays: DefaultMaxIgnoreAgeDays},
			expected: []OverdueIgnore{
				{
					CVE:     "CVE-2022-29153",
					Package: "github.com/foo/bar@v1.2.3",
					Since:   day(-200),
					AgeDays: 200,
				},
			},
		},
		{
			name:     "renewal younger than the threshold is not overdue",
			lines:    []string{entrySince(-10)},
			policy:   IgnorePolicy{ReportOverdue: true, MaxAgeDays: DefaultMaxIgnoreAgeDays},
			expected: []OverdueIgnore{},
		},
		{
			name:     "renewal of an entry without a first ignore date is not overdue",
			lines:    []string{fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0", day(3))},
			policy:   IgnorePolicy{ReportOverdue: true, MaxAgeDays: DefaultMaxIgnoreAgeDays},
			expected: []OverdueIgnore{},
		},
		{
			name:     "first ignore is never overdue",
			lines:    []string{},
			policy:   IgnorePolicy{ReportOverdue: true, MaxAgeDays: DefaultMaxIgnoreAgeDays},
			expected: []OverdueIgnore{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vulnerabilities := []Vulnerability{{ID: "CVE-2022-29153"}}

			_, overdue := updateNancyIgnoreLines(tc.lines, vulnerabilities, p, tc.policy)
			require.Equal(t, tc.expected, overdue)
		})
	}
}

func TestIgnoreVulnerabilities(t *testing.T) {
	p := testPackage(t)
	path := filepath.Join(t.TempDir(), ".nancy-ignore")

	// A missing file is created with the first entry.
	overdue, err := IgnoreVulnerabilities([]Vulnerability{{ID: "CVE-2022-29153"}}, p, path, IgnorePolicy{})
	require.NoError(t, err)
	require.Empty(t, overdue)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, fresh("CVE-2022-29153", day(0))+"\n", string(content))

	// A second run renews the entry and keeps the first ignore date.
	require.NoError(t, os.WriteFile(path, []byte(
		fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0 since=%s\n", day(3), day(-200)),
	), 0640))

	overdue, err = IgnoreVulnerabilities(
		[]Vulnerability{{ID: "CVE-2022-29153"}},
		p,
		path,
		IgnorePolicy{ReportOverdue: true, MaxAgeDays: DefaultMaxIgnoreAgeDays},
	)
	require.NoError(t, err)
	require.Equal(t, []OverdueIgnore{{
		CVE:     "CVE-2022-29153",
		Package: "github.com/foo/bar@v1.2.3",
		Since:   day(-200),
		AgeDays: 200,
	}}, overdue)

	content, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, fresh("CVE-2022-29153", day(-200))+"\n", string(content))
}

func TestIgnoreVulnerabilitiesKeepsALastLineWithoutNewline(t *testing.T) {
	p := testPackage(t)
	path := filepath.Join(t.TempDir(), ".nancy-ignore")
	other := fmt.Sprintf("CVE-2021-00001 until=%s # github.com/baz/qux@v1.0.0 since=%s", day(3), day(-1))
	require.NoError(t, os.WriteFile(path, []byte(other), 0o600))

	_, err := IgnoreVulnerabilities([]Vulnerability{{ID: "CVE-2022-29153"}}, p, path, IgnorePolicy{})
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err)
	require.Equal(t, other+"\n"+fresh("CVE-2022-29153", day(0))+"\n", string(content))
}

func TestPruneIgnoreLines(t *testing.T) {
	matchedEntry := fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0 since=%s", day(3), day(-10))
	unmatchedEntry := fmt.Sprintf("CVE-2021-00001 until=%s # github.com/baz/qux@v1.0.0 since=%s", day(3), day(-10))
	expiredEntry := fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0 since=%s", day(-1), day(-40))

	testCases := []struct {
		name            string
		lines           []string
		matched         map[string]bool
		expectedKept    []string
		expectedRemoved []string
	}{
		{
			name:         "entry the scan matched is kept",
			lines:        []string{matchedEntry},
			matched:      map[string]bool{"CVE-2022-29153": true},
			expectedKept: []string{matchedEntry},
		},
		{
			name:            "unexpired entry the scan did not match is removed",
			lines:           []string{matchedEntry, unmatchedEntry},
			matched:         map[string]bool{"CVE-2022-29153": true},
			expectedKept:    []string{matchedEntry},
			expectedRemoved: []string{unmatchedEntry},
		},
		{
			name:            "expired entry is removed",
			lines:           []string{expiredEntry},
			matched:         map[string]bool{"CVE-2022-29153": true},
			expectedKept:    []string{},
			expectedRemoved: []string{expiredEntry},
		},
		{
			name:            "entry without an expiration date is removed",
			lines:           []string{"CVE-2022-29153 # not applicable"},
			matched:         map[string]bool{"CVE-2022-29153": true},
			expectedKept:    []string{},
			expectedRemoved: []string{"CVE-2022-29153 # not applicable"},
		},
		{
			name:            "comment and blank lines are kept",
			lines:           []string{"# mongo-driver v1: no fixed v1 release", "", "  # indented", unmatchedEntry},
			matched:         map[string]bool{},
			expectedKept:    []string{"# mongo-driver v1: no fixed v1 release", "", "  # indented"},
			expectedRemoved: []string{unmatchedEntry},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kept, removed := pruneIgnoreLines(tc.lines, tc.matched)
			require.Equal(t, tc.expectedKept, kept)
			require.Equal(t, tc.expectedRemoved, removed)
		})
	}
}

func TestPruneIgnores(t *testing.T) {
	matchedEntry := fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0 since=%s", day(3), day(-10))
	unmatchedEntry := fmt.Sprintf("CVE-2021-00001 until=%s # github.com/baz/qux@v1.0.0 since=%s", day(3), day(-10))
	content := "# kept\n" + matchedEntry + "\n" + unmatchedEntry + "\n"
	scan := ScanResult{Matched: map[string]bool{"CVE-2022-29153": true}, Audited: 12}

	t.Run("removes the entries the scan did not match", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".nancy-ignore")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		removed, err := PruneIgnores(path, scan)
		require.NoError(t, err)
		require.Equal(t, []string{unmatchedEntry}, removed)

		got, err := os.ReadFile(filepath.Clean(path))
		require.NoError(t, err)
		require.Equal(t, "# kept\n"+matchedEntry+"\n", string(got))
	})

	t.Run("scan that audited nothing leaves the file unchanged", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".nancy-ignore")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		removed, err := PruneIgnores(path, ScanResult{Matched: map[string]bool{}})
		require.NoError(t, err)
		require.Empty(t, removed)

		got, err := os.ReadFile(filepath.Clean(path))
		require.NoError(t, err)
		require.Equal(t, content, string(got))
	})

	t.Run("file with nothing to remove is not rewritten", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".nancy-ignore")
		untouched := "# no trailing newline\n" + matchedEntry
		require.NoError(t, os.WriteFile(path, []byte(untouched), 0o600))

		removed, err := PruneIgnores(path, scan)
		require.NoError(t, err)
		require.Empty(t, removed)

		got, err := os.ReadFile(filepath.Clean(path))
		require.NoError(t, err)
		require.Equal(t, untouched, string(got))
	})

	t.Run("missing file is not created", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".nancy-ignore")

		removed, err := PruneIgnores(path, scan)
		require.NoError(t, err)
		require.Empty(t, removed)
		require.NoFileExists(t, path)
	})
}
