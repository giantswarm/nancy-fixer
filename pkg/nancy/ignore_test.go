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
