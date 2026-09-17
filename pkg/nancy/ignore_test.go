package nancy

import (
	"fmt"
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
	return time.Now().AddDate(0, 0, offsetDays).Format("2006-01-02")
}

func TestGenerateNancyIgnoreEntry(t *testing.T) {
	p := testPackage(t)

	entry := generateNancyIgnoreEntry(Vulnerability{ID: "CVE-2022-29153"}, p)

	require.Equal(t,
		fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.2.3", day(DefaultIgnorePeriodDays)),
		entry,
	)
}

func TestUpdateNancyIgnoreLines(t *testing.T) {
	p := testPackage(t)

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
			expected: []string{
				fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.2.3", day(DefaultIgnorePeriodDays)),
			},
		},
		{
			name:            "renewal of an entry whose vulnerability is still present",
			lines:           []string{fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0", day(3))},
			vulnerabilities: []Vulnerability{{ID: "CVE-2022-29153"}},
			expected: []string{
				fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.2.3", day(DefaultIgnorePeriodDays)),
			},
		},
		{
			name:            "expired entry for a vulnerability that is gone is dropped",
			lines:           []string{fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0", day(-1))},
			vulnerabilities: []Vulnerability{},
			expected:        []string{},
		},
		{
			name:            "unexpired entry for a vulnerability that is gone is kept",
			lines:           []string{fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0", day(3))},
			vulnerabilities: []Vulnerability{},
			expected:        []string{fmt.Sprintf("CVE-2022-29153 until=%s # github.com/foo/bar@v1.0.0", day(3))},
		},
		{
			name:            "line without an expiry date is deleted",
			lines:           []string{"CVE-2022-29153 # not applicable, we do not use this code path"},
			vulnerabilities: []Vulnerability{},
			expected:        []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, updateNancyIgnoreLines(tc.lines, tc.vulnerabilities, p))
		})
	}
}
